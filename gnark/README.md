# ZKGuard Gnark Implementation

This repository contains a `gnark`-based implementation of the ZKGuard policy engine. ZKGuard is a system designed to validate on-chain user actions against a predefined policy list using zk-SNARKs. This implementation ensures that a user's action is compliant with a specific rule without revealing the entire policy set on-chain or within the proving circuit itself.

-----

## 🏛️ Architecture

The core of this ZKGuard implementation is built around efficiency and privacy. Instead of processing an entire list of policy rules within the circuit, the system relies on a **Merkle tree** to commit to the policy set.

Here's how it works:

1.  **Policy Commitment**: Off-circuit, all individual policy rules are hashed and organized into a Merkle tree. The **root** of this tree serves as a succinct cryptographic commitment to the entire policy. This root is made public.
2.  **Proving Process**: To prove that an action is valid, the prover supplies the circuit with:
      * A single **`PolicyLine`** that explicitly allows the action.
      * A **Merkle proof** demonstrating that this specific `PolicyLine` is a legitimate member of the tree that corresponds to the public `PolicyMerkleRoot`.
      * The details of the `UserAction` being performed, along with a valid signature.
3.  **Circuit Verification**: The ZK-SNARK circuit performs three primary checks:
      * **Merkle Proof Verification**: It computes the Merkle root from the provided policy line and the proof path and asserts that this computed root matches the public `PolicyMerkleRoot`.
      * **Signature Verification**: It verifies the user's signature against a hash of the action details (`To || Value || PaddedData`). This proves the action was authorized by the claimed signer.
      * **Policy Compliance**: It verifies that the user's action is fully allowed by the provided `PolicyLine`. The policy model is **allow-only**; any action not explicitly permitted by a matching rule is implicitly blocked.

This architecture ensures that the circuit's complexity remains constant, regardless of the size of the policy. The on-chain or public footprint is minimal—just a single 32-byte hash for the entire policy set.

-----

## 🔐 Cryptographic Primitives

The circuit uses specific hash functions for different purposes to maintain correctness and compatibility with Ethereum standards.

  * **SHA-256**: Used for all non-Ethereum-specific integrity checks.

      * **Policy Merkle Tree**: Leaf and node hashing uses SHA-256.
      * **`CallHash`**: The public commitment to the transaction's calldata is a SHA-256 hash.

  * **Legacy Keccak-256**: Used for all operations requiring Ethereum compatibility. Ethereum uses the original Keccak proposal, which differs slightly from the finalized FIPS-202 SHA-3 standard.

      * **`ecrecover` Message Hash**: The message signed by the user is hashed with legacy Keccak-256.
      * **Address Derivation**: Recovering an Ethereum address from a public key requires hashing the key with legacy Keccak-256.

-----

## ⚡ Circuit Inputs

The `ZKGuardCircuit` is defined with the following public and private inputs:

### Public Inputs

The circuit exposes four 32-byte hashes that serve as public commitments:

  * `CallHash`: The **SHA-256** hash of the user action's calldata, padded to `MAX_DATA_BYTES`.
  * `PolicyMerkleRoot`: The SHA-256 root hash of the policy Merkle tree.
  * `GroupsHash`: A placeholder hash representing the set of address groups.
  * `AllowHash`: A placeholder hash representing allow-lists.

### Private Witness

  * **User Action**: The details of the on-chain action being attempted.
      * `To`, `Value`, `Data`, `DataLen`, `Signer`
      * `SigRHi`, `SigRLo`, `SigSHi`, `SigSLo`: The `secp256k1` signature components, split into 128-bit high/low parts.
      * `SigV`: The signature's recovery ID.
  * **Policy Line**: A single `PolicyLineWitness` that allegedly allows the action.
  * **Merkle Proof**:
      * `MerkleProofSiblings`: The sibling hashes required to reconstruct the Merkle root.
      * `MerkleProofPath`: The path bits (0 for left, 1 for right) indicating the position of the hashes at each level of the tree.
  * **Groups & Allowlists**: The full sets of addresses for groups and allow-lists used in policy evaluation.

-----

## 🚀 How to Run

The `main.go` file serves as a complete, self-contained example that demonstrates the entire lifecycle of creating and verifying a proof.

### Prerequisites

  * Go (version 1.21 or later)

### Steps

1.  **Install Dependencies**: Navigate to the project directory and fetch the required `gnark` modules.
    ```bash
    go mod tidy
    ```
2.  **Run the Example**: Execute the `main.go` file.
    ```bash
    go run main.go
    ```

### What the Script Does

The `main` function in `main.go` executes the following steps:

1.  **Generates Test Data**: Creates a new signer key, an example user action (an ERC-20 token transfer), and a valid signature over the action's hash.
2.  **Builds the Policy**: Defines a single policy rule and pads the remaining leaves with empty data to construct a full, balanced tree.
3.  **Constructs a Merkle Tree**: Builds a SHA-256 Merkle tree from the serialized policy rules.
4.  **Generates a Merkle Proof**: Creates a proof for the specific policy line that will be used in the witness.
5.  **Compiles the Circuit**: Compiles the `ZKGuardCircuit` into a R1CS constraint system.
6.  **Performs Trusted Setup**: Runs the Groth16 setup phase to generate a proving key (`pk`) and a verifying key (`vk`).
7.  **Creates a Witness**: Populates the circuit with the public inputs and the private witness data.
8.  **Generates a Proof**: Uses the proving key and the witness to generate a zk-SNARK proof.
9.  **Verifies the Proof**: Uses the verifying key and the public witness to verify the proof.

If all steps are successful, the script will print a `✅ Proof verified successfully!` message.