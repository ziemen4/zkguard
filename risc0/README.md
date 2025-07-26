## ZKGuard Policies and Proof Generation

ZKGuard works by generating a **zero-knowledge proof (ZKP)** that attests to the "safety" of a user's on-chain action. This safety is determined by checking the action against a predefined security policy. The proof can then be verified on-chain or off-chain without revealing the specific policy details, ensuring both security and privacy.

### The Allow-List Model

The system uses a strict **allow-list model**. The policy consists of a set of rules (`PolicyLine` objects), where each rule explicitly defines a permitted action. If a user's action does not perfectly match at least one `Allow` rule in the policy, it is considered blocked by default. This "default-deny" stance provides a strong security posture.

The entire set of policy rules is committed to a **Merkle root**. This ensures that when a proof is generated for an action, it's not only proving compliance with a rule but also proving that the rule itself is a legitimate part of the established policy set.

### Policy Structure (`PolicyLine`)

Each rule within a policy defines the conditions for an action to be allowed. The structure is as follows:

* **`tx_type`**: The type of transaction.
    * `Transfer`: A native asset (e.g., ETH) or an ERC-20 token transfer.
    * `ContractCall`: Any other interaction with a smart contract.
* **`destination`**: The recipient of the transaction or asset.
    * `Any`: Any address is permitted.
    * `Group(name)`: The address must belong to a predefined group (e.g., "Team Wallets").
    * `Allowlist(name)`: The address must be on a specific, named allow-list (e.g., "Approved DeFi Protocols").
* **`signer`**: The address that signed the user action.
    * `Any`: Any signer is permitted.
    * `Exact(address)`: Must be a specific address.
    * `Group(name)`: The signer must belong to a predefined group.
* **`asset`**: The asset being transferred. For `ContractCall`, this is typically ignored.
    * `Any`: Any asset is permitted (or not applicable).
    * `Exact(token_address)`: Must be a specific ERC-20 token address.
* **`action`**: The outcome if all conditions match.
    * `Allow`: The action is permitted. In the current model, this is the only action type used.

### Proof Generation in Risc0

The proof generation happens inside the Risc0 zkVM guest. The guest program receives the following inputs from the host:

1.  The **User Action** to be verified.
2.  A single **Policy Line** that supposedly allows the action.
3.  A **Merkle Path** to prove the policy line's inclusion in the policy set.
4.  The trusted **Merkle Root** of the entire policy set.
5.  Auxiliary data like **Groups** and **Allow-lists**.

The guest then performs two critical verification steps:

1.  **Proof of Membership**: It verifies that the provided `PolicyLine` and `MerklePath` correctly compute to the trusted `Merkle Root`. This cryptographically proves that the rule is authentic.
2.  **Proof of Compliance**: It evaluates the `UserAction` against the `PolicyLine`, ensuring every field (`tx_type`, `destination`, `signer`, `asset`) matches the rule's conditions and that the signature is valid.

If both steps succeed, the zkVM generates a ZKP, which serves as a verifiable seal of approval for the user's action.