use std::time::Duration;
use stratum_core::binary_sv2;
use stratum_core::codec_sv2::{
    HandshakeRole, NoiseEncoder, StandardEitherFrame, StandardNoiseDecoder, State,
};
use stratum_core::common_messages_sv2::{
    MESSAGE_TYPE_SETUP_CONNECTION_ERROR, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
    Protocol as CommonProtocol, SetupConnection, SetupConnectionError, SetupConnectionSuccess,
};
use stratum_core::framing_sv2::framing::{HandShakeFrame, Sv2Frame};
use stratum_core::noise_sv2::{INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE, Initiator};
use stratum_core::parsers_sv2::{AnyMessage, CommonMessages, IsSv2Message};
use sv2_compiler::CompilerContext;
use sv2_ir::{Instruction, Operation, Script, Sv2Protocol, Variable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BLITZPOOL_ADDR: &str = "blitzpool.yourdevice.ch:3333";
const BLITZPOOL_AUTH_KEY: &str = "9bCoFxTszKCuffyywH5uS5o6WcU4vsjTH2axxc7wE86y2HhvULU";
const TIMEOUT: Duration = Duration::from_secs(10);

pub fn decode_authority_pubkey(b58: &str) -> Result<[u8; 32], String> {
    let decoded = bs58::decode(b58)
        .with_check(None)
        .into_vec()
        .map_err(|e| format!("Base58 decode error: {e}"))?;
    if decoded.len() < 34 {
        return Err(format!("Key too short: length {}", decoded.len()));
    }
    let version = u16::from_le_bytes(decoded[..2].try_into().unwrap());
    if version != 1 {
        return Err(format!("Unsupported key version: {version}"));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded[2..34]);
    Ok(key)
}

async fn run_scenario(name: &str, script: Script) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n============================================================");
    println!(" Scenario: {name}");
    println!("============================================================");

    // 1. Compile script with sv2-compiler
    let mut compiler = CompilerContext::new();
    compiler.variables.push(Variable::MiningDevice);
    compiler.variables.push(Variable::Pool);
    let messages = compiler.compile_script(&script)?;
    let setup_msg = &messages[0];

    let mut f = Sv2Frame::<SetupConnection, Vec<u8>>::from_bytes(setup_msg.wire_bytes.clone())
        .map_err(|e| format!("SizeHint error: {e:?}"))?;
    let raw_setup: SetupConnection =
        binary_sv2::from_bytes(f.payload()).map_err(|e| format!("Parse error: {e:?}"))?;
    println!(
        "  [Compiler] Generated SetupConnection: min_ver={}, max_ver={}, flags=0x{:08x}",
        raw_setup.min_version, raw_setup.max_version, raw_setup.flags
    );

    // 2. Connect and execute Noise handshake
    let auth_key_bytes = decode_authority_pubkey(BLITZPOOL_AUTH_KEY)?;
    let stream = tokio::time::timeout(TIMEOUT, TcpStream::connect(BLITZPOOL_ADDR))
        .await
        .map_err(|_| "Connection timed out")?
        .map_err(|e| format!("TCP connect failed: {e}"))?;
    let (mut reader, mut writer) = stream.into_split();

    let initiator = Initiator::from_raw_k(auth_key_bytes)
        .map_err(|e| format!("Failed to create Initiator: {e:?}"))?;
    let role = HandshakeRole::Initiator(initiator);
    let mut peer_state = State::not_initialized(&role);
    let mut state = State::initialized(role);
    let mut encoder = NoiseEncoder::<AnyMessage<'static>>::new();
    let mut decoder = StandardNoiseDecoder::<AnyMessage<'static>>::new();

    let first_msg = state.step_0().map_err(|e| format!("{e:?}"))?;
    let buffer = encoder
        .encode(StandardEitherFrame::HandShake(first_msg), &mut state)
        .map_err(|e| format!("Encode step 0 error: {e:?}"))?;
    let buf_bytes: &[u8] = buffer.as_ref();
    writer.write_all(buf_bytes).await?;

    let second_msg = tokio::time::timeout(TIMEOUT, async {
        loop {
            let mut buf = vec![0u8; decoder.writable_len()];
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|e| format!("Read error: {e}"))?;
            decoder.writable().copy_from_slice(&buf);
            match decoder.next_frame(&mut peer_state) {
                Ok(msg) => return Ok(msg),
                Err(stratum_core::codec_sv2::Error::MissingBytes(_)) => continue,
                Err(e) => return Err(format!("Codec error: {e:?}")),
            }
        }
    })
    .await
    .map_err(|_| "Timed out waiting for handshake response")?
    .map_err(|e| format!("Handshake receive failed: {e}"))?;

    let handshake_frame: HandShakeFrame = second_msg
        .try_into()
        .map_err(|e| format!("Invalid handshake frame: {e:?}"))?;
    let payload: [u8; INITIATOR_EXPECTED_HANDSHAKE_MESSAGE_SIZE] = handshake_frame
        .get_payload_when_handshaking()
        .try_into()
        .map_err(|_| "Invalid handshake payload size")?;

    let transport_state = state.step_2(payload).map_err(|e| format!("{e:?}"))?;
    state = transport_state;
    println!("  [Transport] Noise authenticated channel established.");

    // 3. Send compiled SetupConnection frame over encrypted transport
    let setup_msg = SetupConnection {
        protocol: CommonProtocol::MiningProtocol,
        min_version: raw_setup.min_version,
        max_version: raw_setup.max_version,
        flags: raw_setup.flags,
        endpoint_host: "127.0.0.1".try_into().unwrap(),
        endpoint_port: 34254,
        vendor: "stratum-sim".try_into().unwrap(),
        hardware_version: "1.0".try_into().unwrap(),
        firmware: "0.1".try_into().unwrap(),
        device_id: "".try_into().unwrap(),
    };
    let any_msg = AnyMessage::Common(CommonMessages::SetupConnection(setup_msg));
    let msg_type = any_msg.message_type();
    let frame = StandardEitherFrame::<AnyMessage<'static>>::Sv2(
        Sv2Frame::from_message(any_msg, msg_type, 0, false)
            .ok_or("Failed to construct Sv2Frame")?,
    );

    let encrypted_buf = encoder
        .encode(frame, &mut state)
        .map_err(|e| format!("Encryption error: {e:?}"))?;
    let enc_bytes: &[u8] = encrypted_buf.as_ref();
    writer.write_all(enc_bytes).await?;
    println!(
        "  [Transport] Transmitted SetupConnection ({} bytes wire).",
        enc_bytes.len()
    );

    // 4. Read response from pool
    let response = tokio::time::timeout(TIMEOUT, async {
        loop {
            let mut buf = vec![0u8; decoder.writable_len()];
            reader
                .read_exact(&mut buf)
                .await
                .map_err(|e| format!("Read error: {e}"))?;
            decoder.writable().copy_from_slice(&buf);
            match decoder.next_frame(&mut state) {
                Ok(frame) => return Ok(frame),
                Err(stratum_core::codec_sv2::Error::MissingBytes(_)) => continue,
                Err(e) => return Err(format!("Codec error while reading response: {e:?}")),
            }
        }
    })
    .await
    .map_err(|_| "Timed out waiting for pool response")?
    .map_err(|e| format!("Pool response read failed: {e}"))?;

    match response {
        StandardEitherFrame::Sv2(mut frame) => {
            let header = frame
                .get_header()
                .ok_or("Missing header in response frame")?;
            let msg_type = header.msg_type();

            match msg_type {
                MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS => {
                    let success: SetupConnectionSuccess = binary_sv2::from_bytes(frame.payload())
                        .map_err(|e| {
                        format!("Failed to parse SetupConnectionSuccess: {e:?}")
                    })?;
                    println!("  [Pool Result] -> 0x01 SetupConnection.Success");
                    println!("    * Negotiated Version : {}", success.used_version);
                    println!("    * Pool Flags         : 0x{:08x}", success.flags);
                }
                MESSAGE_TYPE_SETUP_CONNECTION_ERROR => {
                    let error: SetupConnectionError = binary_sv2::from_bytes(frame.payload())
                        .map_err(|e| format!("Failed to parse SetupConnectionError: {e:?}"))?;
                    println!("  [Pool Result] -> 0x02 SetupConnection.Error");
                    println!(
                        "    * Error Code         : \"{}\"",
                        error.error_code.as_utf8_or_hex()
                    );
                    println!("    * Unsupported Flags  : 0x{:08x}", error.flags);
                }
                other => {
                    println!("  [Pool Result] -> Unexpected message type 0x{:02x}", other);
                }
            }
        }
        StandardEitherFrame::HandShake(_) => {
            println!("  [Pool Result] -> Unexpected HandShake frame in transport mode");
        }
    }

    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("=== Stratum-Sim Live Runner: Target Blitzpool ===");

    // Scenario 1: Valid Handshake (Request version 2)
    let valid_script = Script {
        instructions: vec![
            Instruction {
                inputs: vec![0, 1],
                operation: Operation::InitConnection,
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadProtocol(Sv2Protocol::Mining),
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadProtocolVersion(2),
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadProtocolVersion(2),
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadFlags(0),
            },
            Instruction {
                inputs: vec![2, 3, 4, 5, 6],
                operation: Operation::SetupConnection,
            },
        ],
    };
    run_scenario("Valid Handshake (v2..v2)", valid_script).await?;

    // Scenario 2: Failed Handshake - Protocol Version Mismatch (Request version 3)
    let version_mismatch_script = Script {
        instructions: vec![
            Instruction {
                inputs: vec![0, 1],
                operation: Operation::InitConnection,
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadProtocol(Sv2Protocol::Mining),
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadProtocolVersion(3),
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadProtocolVersion(3),
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadFlags(0),
            },
            Instruction {
                inputs: vec![2, 3, 4, 5, 6],
                operation: Operation::SetupConnection,
            },
        ],
    };
    run_scenario(
        "Failed Handshake: Version Mismatch (v3..v3)",
        version_mismatch_script,
    )
    .await?;

    // Scenario 3: Failed Handshake - Unsupported Feature Flags (0xFFFFFFFF)
    let unsupported_flags_script = Script {
        instructions: vec![
            Instruction {
                inputs: vec![0, 1],
                operation: Operation::InitConnection,
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadProtocol(Sv2Protocol::Mining),
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadProtocolVersion(2),
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadProtocolVersion(2),
            },
            Instruction {
                inputs: vec![],
                operation: Operation::LoadFlags(0xFFFFFFFF),
            },
            Instruction {
                inputs: vec![2, 3, 4, 5, 6],
                operation: Operation::SetupConnection,
            },
        ],
    };
    run_scenario(
        "Failed Handshake: Unsupported Flags (all bits set)",
        unsupported_flags_script,
    )
    .await?;

    println!("\n=== All Scenarios Finished ===");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_blitzpool_authority_key() {
        let key = decode_authority_pubkey(BLITZPOOL_AUTH_KEY).expect("Must decode");
        assert_eq!(key.len(), 32);
    }
}
