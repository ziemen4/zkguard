# ZKGuard: `gnark` Implementation

This directory contains a `gnark`-based zk-SNARK implementation of the ZKGuard policy engine. It uses the Groth16 proving system to generate and verify proofs of policy compliance for on-chain actions.

This implementation is designed for high performance and minimal proof size, making it well-suited for direct on-chain verification.

## 🏛️ Architecture

Following the core ZKGuard design, this implementation relies on a **Merkle tree** to commit to the policy set, ensuring the circuit's complexity remains constant regardless of the number of policy rules. The verification logic is encoded into a fixed arithmetic circuit.

A proof generated with this implementation validates two core properties:
1.  **Proof of Membership**: The circuit verifies a Merkle proof for a given `PolicyLine` against a public `PolicyMerkleRoot`. This confirms the rule is an authentic part of the committed policy.
2.  **Proof of Compliance**: The circuit verifies that the user's action (including transaction details and signatures) fully complies with the constraints of that authenticated `PolicyLine`.

### 🔐 Cryptographic Primitives

The circuit uses specific hash functions for different purposes to maintain correctness and compatibility with Ethereum standards.

* **SHA-256**: Used for all non-Ethereum-specific integrity checks.
    * **Policy Merkle Tree**: Hashing of policy lines and intermediate nodes.
    * **`CallHash`**: The public commitment to the transaction's calldata.
* **Legacy Keccak-256**: Used for all operations requiring Ethereum compatibility.
    * **`ecrecover` Message Hash**: The message signed by the user is hashed with legacy Keccak-256 to be compatible with standard wallet signatures.
    * **Address Derivation**: Recovering an Ethereum address from a public key.

## 📜 Policy Structure

A policy is defined by a `PolicyLine` struct, which specifies the conditions for an action to be allowed. The key fields and patterns are:

* `TxType`: `TT_TRANSFER` (for ETH or ERC20) or `TT_CONTRACTCALL`.
* `DestinationTag`: `DP_ANY`, `DP_GROUP` (destination is in a group), or `DP_ALLOWLIST`.
* `SignerTag`:
    * `SP_ANY`: Any valid signature.
    * `SP_EXACT`: A specific signer address.
    * `SP_GROUP`: The signer must be a member of a specified group.
    * `SP_THRESHOLD`: A minimum number of signers (`Threshold`) from a specified group (`SignerGroupIdx`) must have signed the action.
* `AssetTag`: `AP_ANY` or `AP_EXACT` (a specific token address).
* `AmountMax`: An optional maximum value for transfers.
* `FunctionSelector`: An optional 4-byte selector to restrict contract calls to a specific function.

## ⚡ Circuit Inputs

The `ZKGuardCircuit` is defined with the following public and private inputs:

### Public Inputs
The circuit exposes four 32-byte hashes that serve as public commitments:
* `CallHash`: The SHA-256 hash of the user action's calldata.
* `PolicyMerkleRoot`: The SHA-256 root hash of the policy Merkle tree.
* `GroupsHash`: A placeholder hash representing the set of address groups.
* `AllowHash`: A placeholder hash representing allow-lists.

### Private Witness
* **User Action**: The details of the on-chain action being attempted, including `To`, `Value`, `Data`, and one or more ECDSA signatures.
* **Policy Line**: A single `PolicyLineWitness` that allegedly allows the action.
* **Merkle Proof**: The sibling hashes and path bits needed to prove the policy line's membership in the tree.
* **Groups & Allowlists**: The full address sets required for policy evaluation.

## 🚀 How to Run

The `main.go` file provides a CLI to run various DAO policy examples, while `bench_test.go` can be used to measure performance.

### Prerequisites
* Go (version 1.23 or later)

### Running Examples
1.  **Install Dependencies**: Navigate to the `gnark` directory and fetch the required modules.
    ```bash
    go mod tidy
    ```
2.  **Run an Example**: You can run a single example or all of them. The `--prove` flag controls whether to perform a quick logic check or generate a full ZK-SNARK proof.

    * **Run a specific example (logic check only):**
        ```bash
        go run ./src/... -example advanced_signer_policies
        ```
    * **Run all examples and generate full proofs:**
        ```bash
        go run ./src/... -example all --prove
        ```

### Running Benchmarks
To benchmark the performance of circuit compilation, setup, proving, and verification, run the following command:
```bash
go test -bench . -benchmem
```

This will execute the scenarios defined in bench_test.go and report the time and memory allocations for each phase.

