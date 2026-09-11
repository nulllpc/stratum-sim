//! # Stratum V2 Intermediate Representation (`sv2-ir`)
//!
//! Declarative, register-based representation for Stratum V2 protocol interactions.
//!
//! ## What This Solves
//! - **Dynamic Causal Binding**: Messages reference runtime-allocated handles (negotiated versions,
//!   pool-assigned channel IDs) via typed registers ([`Variable`]) instead of hardcoded values.
//! - **Structured Fuzzing & Shrinking**: Allows generators to mutate valid protocol flows
//!   (reordering, invalid flags, premature messages) without breaking Noise crypto, and shrink
//!   failing traces to minimal reproducing scripts.
//! - **Transport Agnostic**: Decouples protocol intent from execution. The same [`Script`] can drive
//!   live TCP/Noise sessions (`sv2-executor`) or in-memory actor harnesses.
//!
//! ## Structure
//! - [`Script`]: Linear sequence of [`Instruction`]s.
//! - [`Instruction`]: Binds an [`Operation`] to input variable indices.
//! - [`Operation`]: Protocol action (load constant, init connection, send/receive message).
//! - [`Variable`]: Typed state in the execution environment.

/// The sub-protocols defined in SV2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sv2Protocol {
    Mining,
    JobNegotiation,
    TemplateDistribution,
}

/// The types of state tracked by the fuzzer.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Variable {
    // --- Network Topology ---
    Connection,
    Session,

    // --- Components ---
    Pool,
    JdClient,
    JdServer,
    Translator,
    MiningDevice,
    TemplateProvider,

    // --- SetupConnection Primitives ---
    Protocol(Sv2Protocol),
    ProtocolVersion(u16),
    Flags(u32),
    ErrorCode(String),
}

/// Operations are the actions the fuzzer can take.
#[derive(Debug, Clone, PartialEq)]
pub enum Operation {
    // --- Load Primitives ---
    LoadProtocol(Sv2Protocol),
    LoadProtocolVersion(u16),
    LoadFlags(u32),
    LoadErrorCode(String),

    // --- Network Actions ---
    /// Creates a TCP link. Inputs: Client Component, Server Component
    InitConnection,

    /// Sends SetupConnection (Client -> Server, Spec §3.6.1).
    /// Inputs: Connection, Protocol, MinVersion, MaxVersion, Flags
    SetupConnection,

    /// Sends SetupConnection.Success (Server -> Client, Spec §3.6.2).
    /// Inputs: Connection, ProtocolVersion (used_version), Flags
    SetupConnectionSuccess,

    /// Sends SetupConnection.Error (Server -> Client, Spec §3.6.3).
    /// Inputs: Connection, Flags, ErrorCode
    SetupConnectionError,
}

/// An instruction executed by the fuzzer.
#[derive(Debug, Clone, PartialEq)]
pub struct Instruction {
    /// Indices pointing to the variables this operation consumes as inputs.
    pub inputs: Vec<usize>,
    /// The action to perform.
    pub operation: Operation,
}

/// An ordered sequence of instructions forming a test scenario.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Script {
    pub instructions: Vec<Instruction>,
}

impl Operation {
    /// How many input variables does this operation require?
    pub fn num_inputs(&self) -> usize {
        match self {
            Self::LoadProtocol(_)
            | Self::LoadProtocolVersion(_)
            | Self::LoadFlags(_)
            | Self::LoadErrorCode(_) => 0,
            Self::InitConnection => 2,         // Client, Server
            Self::SetupConnection => 5, // Connection, Protocol, MinVersion, MaxVersion, Flags
            Self::SetupConnectionSuccess => 3, // Connection, UsedVersion, Flags
            Self::SetupConnectionError => 3, // Connection, Flags, ErrorCode
        }
    }

    /// How many output variables does this operation produce?
    pub fn num_outputs(&self) -> usize {
        match self {
            Self::SetupConnection | Self::SetupConnectionSuccess => 1, // Outputs a Session
            Self::SetupConnectionError => 0, // Terminal on error, no session established
            _ => 1, // Load operations and InitConnection output exactly 1 variable
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_setup_connection_script_construction() {
        let script = Script {
            instructions: vec![
                // 0: Client component
                Instruction {
                    inputs: vec![],
                    operation: Operation::LoadProtocol(Sv2Protocol::Mining),
                },
                // 1: ProtocolVersion 2
                Instruction {
                    inputs: vec![],
                    operation: Operation::LoadProtocolVersion(2),
                },
                // 2: Flags 0
                Instruction {
                    inputs: vec![],
                    operation: Operation::LoadFlags(0),
                },
                // 3: SetupConnection
                Instruction {
                    // Referencing Connection (assume idx 0), Protocol (1), MinVer (2), MaxVer (2), Flags (3)
                    inputs: vec![0, 1, 2, 2, 3],
                    operation: Operation::SetupConnection,
                },
                // 4: SetupConnectionSuccess response: Connection (0), UsedVer (2), Flags (3)
                Instruction {
                    inputs: vec![0, 2, 3],
                    operation: Operation::SetupConnectionSuccess,
                },
            ],
        };

        assert_eq!(script.instructions.len(), 5);
        assert_eq!(script.instructions[3].operation.num_inputs(), 5);
        assert_eq!(script.instructions[4].operation.num_inputs(), 3);
        assert_eq!(script.instructions[4].operation.num_outputs(), 1);
    }
}
