# ZKGuard: A Zero-Knowledge Policy Engine for On-Chain Actions

ZKGuard is a high-assurance security system designed to enforce customizable policies on blockchain transactions before they are executed. It uses the power of zero-knowledge proofs (ZKPs) to validate that a user's action complies with a predefined security policy, without revealing the policy itself.

This provides a powerful combination of security and privacy, making it ideal for securing DAO treasuries, smart contract wallets, and other critical on-chain infrastructure.

## Core Concept: The Allow-List Model

The system operates on a strict **allow-list model**. A policy is a set of rules, where each rule explicitly defines a permitted action (e.g., "Allow transfers of up to 10,000 USDC to addresses in the 'Team Wallets' group"). Any action that does not match at least one "allow" rule is implicitly blocked. This "default-deny" posture provides a robust security foundation.

To avoid placing the entire, potentially large, policy set on-chain, we commit to it using a **Merkle tree**. The root of this tree is the only piece of information that needs to be made public, serving as a succinct cryptographic fingerprint of the entire policy.

## The Two-Part Proof Architecture

The fundamental innovation of ZKGuard is how it proves that an action is valid. The generated zero-knowledge proof is not a monolithic check; it's a cryptographic testament to two distinct but connected claims:

1.  **Proof of Membership**: This part of the proof confirms that the rule being used for validation is authentic and unaltered. The prover supplies the ZK circuit/VM with a single policy rule and a Merkle proof (a list of sibling hashes). The ZKP logic then re-calculates the Merkle root from this data and asserts that it matches the publicly known, trusted `PolicyMerkleRoot`. This proves the rule is a legitimate part of the committed policy set without revealing any other rules.

2.  **Proof of Compliance**: Once the rule's authenticity is established via the Proof of Membership, this part of the proof confirms that the user's action strictly adheres to the conditions of that rule. The ZKP logic evaluates every field of the user's action (`to`, `value`, `data`, `signer(s)`) against the constraints defined in the policy rule (`DestinationPattern`, `AssetPattern`, `SignerPattern`, etc.). This includes verifying the cryptographic signature(s) to ensure the action was authorized by the correct party.

By combining these two proofs into a single ZKP, ZKGuard provides a powerful guarantee: "I can prove this action is authorized by a valid rule within the committed policy, and I can do so without revealing which rule or any other part of the policy."

### Benefits
* **Privacy**: The entire policy set remains confidential. Only the Merkle root is public.
* **Efficiency**: The complexity of the proof is constant regardless of the number of rules in the policy. This is a huge advantage over systems that might need to loop through many rules on-chain.
* **Security**: Policies are enforced by immutable cryptography, removing reliance on centralized intermediaries or fallible multi-sig signers.
* **Flexibility**: Policies can be updated off-chain by simply publishing a new Merkle root.

## Implementations

This repository contains three parallel implementations of the ZKGuard engine, demonstrating different ZK technologies:

### 🔵 `gnark` (Go) - zk-SNARKs
This implementation uses the `gnark` library to build a **Groth16 zk-SNARK circuit**. It is highly optimized for performance and generates extremely small proofs, making it ideal for on-chain verification where gas costs are a primary concern.

➡️ **[See the `gnark` README for technical details and instructions.](./gnark/README.md)**

### ⚫️ `noir` (Noir Language) - zk-SNARKs
This implementation uses the `noir` language and the `bb.js` backend to build a **Plonk zk-SNARK circuit**. Noir is a domain-specific language for creating and verifying zero-knowledge proofs, designed for ease of use and developer productivity.

➡️ **[See the `noir` README for technical details and instructions.](./noir/README.md)**



### 🔴 `risc0` (Rust) - zkVM
This implementation uses the **Risc0 zkVM**, a general-purpose zero-knowledge virtual machine. Instead of designing a circuit, we write standard Rust code that executes inside the zkVM to perform the validation. This approach offers greater flexibility for writing highly complex and expressive policies.

➡️ **[See the `risc0` README for technical details and instructions.](./risc0/README.md)**

## Contributing

We welcome contributions from the community! Whether it's reporting a bug, proposing a new feature, or submitting a pull request, your input is valuable.

Please see our **[CONTRIBUTING.md](./CONTRIBUTING.md)** file for detailed guidelines on how to get started with contributing to the project.

## License

This project is licensed under the Apache 2.0 License.

See the **[LICENSE.md](./LICENSE.md)** file for the full license text.