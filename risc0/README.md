# ZKGuard: Risc0 (zkVM) Implementation

This directory contains a `risc0`-based implementation of the ZKGuard policy engine. It leverages a Zero-Knowledge Virtual Machine (zkVM) to prove policy compliance by executing a standard Rust program in a verifiable manner.

This approach provides significant flexibility, allowing for complex, expressive policies to be written in a general-purpose language without the need to design low-level arithmetic circuits.

## 🏛️ Architecture: Host & Guest

The zkVM model separates the program into two parts: a **host** and a **guest**.

* **Host Program** (`examples/dao_prover.rs`): This is an untrusted program that runs on a standard machine. Its primary role is to prepare all the necessary inputs for the proof. This includes loading the user's action, the specific policy rule that allows it, the corresponding Merkle proof, and any required context like address groups and allow-lists. It then invokes the guest program within the zkVM.

* **Guest Program** (`methods/guest/src/bin/zkguard_policy.rs`): This is the trusted program whose execution is proven. It runs inside the Risc0 zkVM. The guest receives the inputs from the host and performs the complete two-part verification:
    1.  **Proof of Membership**: It verifies that the provided `PolicyLine` and `MerklePath` correctly compute to the trusted `Merkle Root`. This cryptographically proves that the rule is an authentic part of the established policy set.
    2.  **Proof of Compliance**: It evaluates the `UserAction` against the now-authenticated `PolicyLine`. This involves checking the transaction type, destination, asset, amount, function selectors, and, critically, verifying all cryptographic signatures.

If both steps succeed, the zkVM generates a ZKP (`Receipt`) which contains a `Journal`. The guest commits the public hashes of the inputs (`CallHash`, `PolicyMerkleRoot`, `GroupsHash`, `AllowHash`) to this journal, making them available for public verification.

## 📜 Policy Structure

Policies are defined using Rust structs and enums located in the `zkguard_core` crate. This enables strong typing and expressive patterns.

* `PolicyLine`: The core struct defining a single rule.
* `TxType`: `Transfer` or `ContractCall`.
* `DestinationPattern`:
    * `Any`
    * `Group(String)`: Destination must be in a named group (e.g., "TeamWallets").
    * `Allowlist(String)`: Destination must be in a named list (e.g., "ApprovedDEXs").
* `SignerPattern`:
    * `Any`: Any valid signature.
    * `Exact([u8; 20])`: A specific signer address.
    * `Group(String)`: The signer must belong to a named group.
    * `Threshold { group: String, threshold: u8 }`: A minimum number of signers from a named group must have signed.
* `AssetPattern`: `Any` or `Exact([u8; 20])` (a specific token address).

## 🚀 How to Run

The project uses the Rust toolchain and Cargo for building and running. The `dao_prover` example serves as the main entry point for generating proofs for various predefined DAO security policies.

### Prerequisites
* Rust, configured with the toolchain specified in `rust-toolchain.toml`. If you have `rustup` installed, it will automatically use the correct version when you are in this directory.
    ```bash
    rustup toolchain install 1.86.0
    ```

### Running Examples

To run any of the examples, use the `dao_prover` example runner from the `risc0` directory. Specify the policy you want to test using the `--example` flag.

1.  **Run the "Contributor Payments" example:**
    ```bash
    cargo run --release --example dao_prover -- --example contributor_payments
    ```
2.  **Run the "Advanced Signer Policies" (2-of-2 threshold) example:**
    ```bash
    cargo run --release --example dao_prover -- --example advanced_signer_policies
    ```

A full list of available examples can be found in `examples/README.md`. Each run will execute the host program, which invokes the zkVM to prove the action, and finally verifies the generated proof.

## ⛓️ On-Chain Verification

The generated proof (`Receipt`) can be verified on an EVM-compatible blockchain. The `contracts/src/ZKGuard.sol` contract provides a reference implementation for this.

The `verifyAndForward` function accepts the Risc0 `seal` (the proof) and the `journal`. It performs the following checks:
1.  Calls the Risc0 verifier contract to verify the integrity of the proof itself.
2.  Asserts that the public hashes committed in the journal match the trusted hashes stored in the `ZKGuard` contract's state (`policy_hash`, `groups_hash`, etc.).
3.  If verification succeeds, it decodes the `userAction` and forwards the call to its intended destination.