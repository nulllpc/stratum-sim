# Stratum-Sim

Deterministic simulation and protocol-aware scenario generation framework for the Stratum V2 (SV2) Reference Implementation (SRI).

## Rationale

Testing distributed protocol implementations typically falls into two extremes:

1. **Conventional Integration Testing:** End-to-end tests exercise components over OS sockets with real-time async runtimes. While necessary for basic sanity checks, they suffer from fundamental structural limitations:
   * **Nondeterminism & Flakiness:** Task scheduling, OS socket timing, and network latency vary across runs, normalizing transient CI failures and obscuring real regressions.
   * **Unreproducible Races:** When a timing bug, race condition, or deadlock occurs, reproducing the exact interleaving of events is difficult or impossible.
   * **Limited Exploration:** Tests only validate the explicit paths developers anticipate and hand-code, leaving vast state spaces unexercised.

2. **Byte-Level Fuzzing:** Low-level fuzzers feed malformed byte streams into deserializers to catch memory corruption and panics. However, they operate strictly at the parser boundary—they have no concept of protocol state, message hierarchies, or multi-role workflows.

### The Approach: Protocol-Aware Simulation

`stratum-sim` addresses this gap by elevating test generation and simulation to the **state-machine level**:

* **Protocol Grammar via Intermediate Representation (IR):** Rather than generating random socket bytes or building a generic network simulator, we model SV2 message dependencies, semantic variables, and valid state transitions top-down. This enables automatic generation of structured, stateful scenario sequences.
* **Deterministic Execution:** Execution is governed by a seed. Asynchronous scheduling, event ordering, and simulated network delays derive from this seed, making every discovered bug 100% reproducible.
* **Invariant-Driven Validation:** System guarantees (e.g., channel isolation, valid negotiation, share difficulty accounting) are continually asserted across generated traces.

---

## Architecture

The project is structured as a multi-crate Rust workspace:

```
stratum-sim/
├── sv2-ir/          # Core protocol grammar, operations, variables, and script definitions
├── sv2-compiler/    # Lowers IR scripts into spec-compliant binary SV2 wire frames
└── sv2-executor/    # Encrypted transport runner and deterministic execution engine
```

### 1. `sv2-ir` (Protocol Grammar)
Defines semantic variables, operations, and instructions:
* **Semantic Variables:** Enforces type and dependency safety (e.g. `Connection`, `Session`, `Protocol`, `ProtocolVersion`, `Flags`, `ErrorCode`).
* **Operations:** Models protocol actions (`InitConnection`, `SetupConnection`, `SetupConnectionSuccess`, `SetupConnectionError`).
* **Scripts:** Ordered sequences of instructions that specify message hierarchy and parameter flow.

### 2. `sv2-compiler` (Wire Compiler)
Translates abstract IR scripts into binary wire representations:
* Maps IR operations into SRI's `common_messages_sv2` structures.
* Encapsulates messages in standard 6-byte SV2 wire frames (`framing_sv2`).
* Performs compile-time semantic checks ensuring required inputs and types exist before emission.

### 3. `sv2-executor` (Execution Engine)
Connects to target SV2 nodes and evaluates scenario execution:
* Handles the authenticated SV2 **Noise Protocol** handshake (initiator role) using the target node's Secp256k1 authority public key.
* Exchanges encrypted SV2 frames over the transport layer.
* Observes and validates target node responses against expected protocol transitions.

> **Note on Current State:** `sv2-executor` is currently implemented as a raw proof-of-concept runner script (`src/main.rs`) proving end-to-end integration against live nodes. We are refactoring it into a modular library (`lib.rs`) with decoupled transport management (`TransportSession`), session state tracking, and an instruction-stepping VM (`ExecutionEngine`).

---

## Current Status: Verified Vertical Slice

We have completed the foundational vertical slice modeling the `SetupConnection` handshake ([SV2 Spec §3.6](https://github.com/stratum-mining/sv2-spec/blob/main/03-Protocol-Overview.md#36-common-messages)).

The implementation has been verified live against a production SV2 pool (**Blitzpool**, `blitzpool.yourdevice.ch:3333`):

1. **Valid Handshake:** Requesting SV2 mining protocol version 2 produces a valid `0x01 SetupConnection.Success`.
2. **Version Mismatch:** Requesting an unsupported version (e.g. version 3) produces `0x02 SetupConnection.Error` with error code `"protocol-version-mismatch"`.
3. **Flag Negotiation:** Requesting all optional feature bits exercises the pool's flag negotiation masking.

*(Note: Live execution currently runs via the PoC driver script in `sv2-executor/src/main.rs` while the execution engine module refactor is underway.)*

---

## Quick Start

### Prerequisites
* Rust 1.88+ (recommended Rust 1.97+)
* Cargo

### Running Workspace Tests
```bash
cargo test --workspace
```

### Running Workspace Linter
```bash
cargo clippy --all-targets -- -D warnings
```

### Running the Live Production Verification
Runs the live proof-of-concept against Blitzpool over an encrypted Noise connection:
```bash
cargo run -p sv2-executor
```

Expected output:
```text
=== Stratum-Sim Live Runner: Target Blitzpool ===

============================================================
 Scenario: Valid Handshake (v2..v2)
============================================================
  [Compiler] Generated SetupConnection: min_ver=2, max_ver=2, flags=0x00000000
  [Transport] Noise authenticated channel established.
  [Transport] Transmitted SetupConnection (80 bytes wire).
  [Pool Result] -> 0x01 SetupConnection.Success
    * Negotiated Version : 2
    * Pool Flags         : 0x00000000

============================================================
 Scenario: Failed Handshake: Version Mismatch (v3..v3)
============================================================
  [Compiler] Generated SetupConnection: min_ver=3, max_ver=3, flags=0x00000000
  [Transport] Noise authenticated channel established.
  [Transport] Transmitted SetupConnection (80 bytes wire).
  [Pool Result] -> 0x02 SetupConnection.Error
    * Error Code         : "protocol-version-mismatch"
    * Unsupported Flags  : 0x00000000
```

---

## Roadmap

> **Methodology:** Lead with the grammar, fill in the logic to execute the test. Each milestone expands the protocol grammar and drives it vertically through compiler lowering and network execution.

* [x] **Milestone 1 (Connection Handshake Slice):**
  * `sv2-ir`: Connection primitives and `SetupConnection` grammar.
  * `sv2-compiler`: Wire framing and binary serialization.
  * `sv2-executor`: Live Noise transport verification against Blitzpool (`Success` and `Error` scenarios via PoC runner script).
* [ ] **Milestone 1.5 (Executor Modularization):**
  * Refactor `sv2-executor` from a monolithic PoC script into a reusable library (`lib.rs`).
  * Decouple transport layer (`NoiseSession` / `PlainSession`) from scenario logic.
  * Introduce `ExecutionEngine` / VM for step-by-step instruction evaluation and pool response feedback into the IR variable pool.
  * Reduce `src/main.rs` to a thin CLI driver.
* [ ] **Milestone 2 (Standard Channel Negotiation Slice):**
  * `sv2-ir`: Grammar for `OpenStandardMiningChannel` / `OpenStandardMiningChannelSuccess`.
  * `sv2-compiler`: Binary lowering of channel opening requests.
  * `sv2-executor`: State machine handling for channel IDs over active encrypted sessions.
* [ ] **Milestone 3 (Work Distribution & Share Submission Slice):**
  * `sv2-ir`: Ingesting `NewExtendedMiningJob` / `SetNewPrevHash` and emitting `SubmitSharesStandard`.
  * `sv2-compiler`: Binary lowering of share submissions and target difficulty tracking.
  * `sv2-executor`: Live submission of shares and tracking pool responses (`SubmitSharesSuccess` / `SubmitSharesError`).
* [ ] **Milestone 4 (Autonomous Scenario Generator):**
  * Rule-guided randomized IR generation (valid and adversarial message interleavings).
  * Automated pipeline feeding generated IR scripts through compiler into the executor.
* [ ] **Milestone 5 (Simulated Environment & Invariant Assertions):**
  * In-process virtual network (simulated latency/loss, mock pool/proxy actors) with seed-based deterministic replay.
  * Protocol invariant assertions (e.g., channel isolation, duplicate share rejection, state machine leak detection).

---

## Author

* **NPC** ([nulllpc@pm.me](mailto:nulllpc@pm.me))
