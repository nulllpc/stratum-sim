use stratum_core::binary_sv2::Str0255;
use stratum_core::common_messages_sv2::{
    MESSAGE_TYPE_SETUP_CONNECTION, MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
    MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, Protocol as CommonProtocol, SetupConnection,
    SetupConnectionError, SetupConnectionSuccess,
};
use stratum_core::framing_sv2::framing::Sv2Frame;
use sv2_ir::{Instruction, Operation, Script, Sv2Protocol, Variable};

#[derive(Debug, PartialEq, Eq)]
pub enum CompileError {
    InvalidInputIndex {
        index: usize,
        total_variables: usize,
    },
    TypeMismatch {
        expected: &'static str,
        found: String,
    },
    MissingInput {
        expected: usize,
        got: usize,
    },
    FramingFailed(String),
    SerializationFailed(String),
}

impl core::fmt::Display for CompileError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidInputIndex {
                index,
                total_variables,
            } => {
                write!(
                    f,
                    "Invalid variable index {index} (current pool size {total_variables})"
                )
            }
            Self::TypeMismatch { expected, found } => {
                write!(f, "Type mismatch: expected {expected}, found {found}")
            }
            Self::MissingInput { expected, got } => {
                write!(f, "Instruction requires {expected} inputs, but got {got}")
            }
            Self::FramingFailed(msg) => write!(f, "Framing failed: {msg}"),
            Self::SerializationFailed(msg) => write!(f, "Serialization failed: {msg}"),
        }
    }
}

impl std::error::Error for CompileError {}

/// A compiled SV2 message ready to be sent over the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledMessage {
    pub msg_type: u8,
    pub wire_bytes: Vec<u8>,
}

/// The compiler context tracking variable state during script evaluation.
#[derive(Debug, Default)]
pub struct CompilerContext {
    pub variables: Vec<Variable>,
    pub messages: Vec<CompiledMessage>,
}

impl CompilerContext {
    pub fn new() -> Self {
        Self::default()
    }

    fn get_var(&self, idx: usize) -> Result<&Variable, CompileError> {
        self.variables
            .get(idx)
            .ok_or(CompileError::InvalidInputIndex {
                index: idx,
                total_variables: self.variables.len(),
            })
    }

    pub fn compile_instruction(&mut self, inst: &Instruction) -> Result<(), CompileError> {
        if inst.inputs.len() != inst.operation.num_inputs() {
            return Err(CompileError::MissingInput {
                expected: inst.operation.num_inputs(),
                got: inst.inputs.len(),
            });
        }

        match &inst.operation {
            Operation::LoadProtocol(proto) => {
                self.variables.push(Variable::Protocol(*proto));
            }
            Operation::LoadProtocolVersion(ver) => {
                self.variables.push(Variable::ProtocolVersion(*ver));
            }
            Operation::LoadFlags(flags) => {
                self.variables.push(Variable::Flags(*flags));
            }
            Operation::LoadErrorCode(code) => {
                self.variables.push(Variable::ErrorCode(code.clone()));
            }
            Operation::InitConnection => {
                self.variables.push(Variable::Connection);
            }
            Operation::SetupConnection => {
                match self.get_var(inst.inputs[0])? {
                    Variable::Connection => (),
                    other => {
                        return Err(CompileError::TypeMismatch {
                            expected: "Connection",
                            found: format!("{other:?}"),
                        });
                    }
                };

                let proto = match self.get_var(inst.inputs[1])? {
                    Variable::Protocol(p) => match p {
                        Sv2Protocol::Mining => CommonProtocol::MiningProtocol,
                        Sv2Protocol::JobNegotiation => CommonProtocol::JobDeclarationProtocol,
                        Sv2Protocol::TemplateDistribution => {
                            CommonProtocol::TemplateDistributionProtocol
                        }
                    },
                    other => {
                        return Err(CompileError::TypeMismatch {
                            expected: "Protocol",
                            found: format!("{other:?}"),
                        });
                    }
                };

                let min_version = match self.get_var(inst.inputs[2])? {
                    Variable::ProtocolVersion(v) => *v,
                    other => {
                        return Err(CompileError::TypeMismatch {
                            expected: "ProtocolVersion",
                            found: format!("{other:?}"),
                        });
                    }
                };

                let max_version = match self.get_var(inst.inputs[3])? {
                    Variable::ProtocolVersion(v) => *v,
                    other => {
                        return Err(CompileError::TypeMismatch {
                            expected: "ProtocolVersion",
                            found: format!("{other:?}"),
                        });
                    }
                };

                let flags = match self.get_var(inst.inputs[4])? {
                    Variable::Flags(f) => *f,
                    other => {
                        return Err(CompileError::TypeMismatch {
                            expected: "Flags",
                            found: format!("{other:?}"),
                        });
                    }
                };

                let host: Str0255 = "127.0.0.1".try_into().map_err(|e| {
                    CompileError::SerializationFailed(format!("Invalid endpoint_host: {e:?}"))
                })?;
                let vendor: Str0255 = "stratum-sim".try_into().map_err(|e| {
                    CompileError::SerializationFailed(format!("Invalid vendor: {e:?}"))
                })?;
                let hw: Str0255 = "1.0".try_into().map_err(|e| {
                    CompileError::SerializationFailed(format!("Invalid hardware: {e:?}"))
                })?;
                let fw: Str0255 = "0.1".try_into().map_err(|e| {
                    CompileError::SerializationFailed(format!("Invalid firmware: {e:?}"))
                })?;
                let dev_id: Str0255 = "".try_into().map_err(|e| {
                    CompileError::SerializationFailed(format!("Invalid device_id: {e:?}"))
                })?;

                let msg = SetupConnection {
                    protocol: proto,
                    min_version,
                    max_version,
                    flags,
                    endpoint_host: host,
                    endpoint_port: 34254,
                    vendor,
                    hardware_version: hw,
                    firmware: fw,
                    device_id: dev_id,
                };

                let frame: Sv2Frame<SetupConnection, Vec<u8>> =
                    Sv2Frame::from_message(msg, MESSAGE_TYPE_SETUP_CONNECTION, 0, false)
                        .ok_or_else(|| {
                            CompileError::FramingFailed("Failed to frame SetupConnection".into())
                        })?;

                let mut wire_bytes = vec![0u8; frame.encoded_length()];
                frame
                    .serialize(&mut wire_bytes)
                    .map_err(|e| CompileError::SerializationFailed(format!("{e:?}")))?;

                self.messages.push(CompiledMessage {
                    msg_type: MESSAGE_TYPE_SETUP_CONNECTION,
                    wire_bytes,
                });
                self.variables.push(Variable::Session);
            }
            Operation::SetupConnectionSuccess => {
                match self.get_var(inst.inputs[0])? {
                    Variable::Connection => (),
                    other => {
                        return Err(CompileError::TypeMismatch {
                            expected: "Connection",
                            found: format!("{other:?}"),
                        });
                    }
                };

                let used_version = match self.get_var(inst.inputs[1])? {
                    Variable::ProtocolVersion(v) => *v,
                    other => {
                        return Err(CompileError::TypeMismatch {
                            expected: "ProtocolVersion",
                            found: format!("{other:?}"),
                        });
                    }
                };

                let flags = match self.get_var(inst.inputs[2])? {
                    Variable::Flags(f) => *f,
                    other => {
                        return Err(CompileError::TypeMismatch {
                            expected: "Flags",
                            found: format!("{other:?}"),
                        });
                    }
                };

                let msg = SetupConnectionSuccess {
                    used_version,
                    flags,
                };

                let frame: Sv2Frame<SetupConnectionSuccess, Vec<u8>> =
                    Sv2Frame::from_message(msg, MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS, 0, false)
                        .ok_or_else(|| {
                            CompileError::FramingFailed(
                                "Failed to frame SetupConnectionSuccess".into(),
                            )
                        })?;

                let mut wire_bytes = vec![0u8; frame.encoded_length()];
                frame
                    .serialize(&mut wire_bytes)
                    .map_err(|e| CompileError::SerializationFailed(format!("{e:?}")))?;

                self.messages.push(CompiledMessage {
                    msg_type: MESSAGE_TYPE_SETUP_CONNECTION_SUCCESS,
                    wire_bytes,
                });
                self.variables.push(Variable::Session);
            }
            Operation::SetupConnectionError => {
                match self.get_var(inst.inputs[0])? {
                    Variable::Connection => (),
                    other => {
                        return Err(CompileError::TypeMismatch {
                            expected: "Connection",
                            found: format!("{other:?}"),
                        });
                    }
                };

                let flags = match self.get_var(inst.inputs[1])? {
                    Variable::Flags(f) => *f,
                    other => {
                        return Err(CompileError::TypeMismatch {
                            expected: "Flags",
                            found: format!("{other:?}"),
                        });
                    }
                };

                let err_str = match self.get_var(inst.inputs[2])? {
                    Variable::ErrorCode(s) => s.as_str(),
                    other => {
                        return Err(CompileError::TypeMismatch {
                            expected: "ErrorCode",
                            found: format!("{other:?}"),
                        });
                    }
                };

                let error_code: Str0255 = err_str.try_into().map_err(|e| {
                    CompileError::SerializationFailed(format!("Invalid error_code: {e:?}"))
                })?;

                let msg = SetupConnectionError { flags, error_code };

                let frame: Sv2Frame<SetupConnectionError, Vec<u8>> =
                    Sv2Frame::from_message(msg, MESSAGE_TYPE_SETUP_CONNECTION_ERROR, 0, false)
                        .ok_or_else(|| {
                            CompileError::FramingFailed(
                                "Failed to frame SetupConnectionError".into(),
                            )
                        })?;

                let mut wire_bytes = vec![0u8; frame.encoded_length()];
                frame
                    .serialize(&mut wire_bytes)
                    .map_err(|e| CompileError::SerializationFailed(format!("{e:?}")))?;

                self.messages.push(CompiledMessage {
                    msg_type: MESSAGE_TYPE_SETUP_CONNECTION_ERROR,
                    wire_bytes,
                });
            }
        }

        Ok(())
    }

    pub fn compile_script(
        &mut self,
        script: &Script,
    ) -> Result<Vec<CompiledMessage>, CompileError> {
        for inst in &script.instructions {
            self.compile_instruction(inst)?;
        }
        Ok(self.messages.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use stratum_core::binary_sv2;

    #[test]
    fn test_compile_setup_connection_to_wire_bytes() {
        let mut compiler = CompilerContext::new();
        // Provide dummy client/server components at indices 0, 1
        compiler.variables.push(Variable::MiningDevice);
        compiler.variables.push(Variable::Pool);

        // Client: 0, Server: 1 -> InitConnection outputs Connection at idx 2
        let script = Script {
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

        let messages = compiler
            .compile_script(&script)
            .expect("Compilation must succeed");
        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].msg_type, MESSAGE_TYPE_SETUP_CONNECTION);

        // Verify deserialization using SRI's framing and parser
        let raw = messages[0].wire_bytes.clone();
        let mut frame = Sv2Frame::<SetupConnection, Vec<u8>>::from_bytes(raw)
            .expect("SRI must deserialize the compiled frame");
        let header = frame.get_header().expect("Header must be valid");
        assert_eq!(header.msg_type(), MESSAGE_TYPE_SETUP_CONNECTION);
        assert_eq!(header.ext_type(), 0);

        let parsed_msg: SetupConnection = binary_sv2::from_bytes(frame.payload())
            .expect("SRI parser must deserialize the payload");
        assert_eq!(parsed_msg.min_version, 2);
        assert_eq!(parsed_msg.max_version, 2);
        assert_eq!(parsed_msg.flags, 0);
    }
}
