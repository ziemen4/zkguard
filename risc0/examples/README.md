# ZKGuard DAO Example 

This directory contains an improved, command-line-driven prover that demonstrates how to use ZKGuard to enforce a set of security policies for a fictional DAO. This version is a flexible tool that allows you to generate a proof for any user action by providing the transaction details as command-line arguments.

## Overview

The prover (`prover.rs`) takes a policy file, group/allowlist definitions, and the details of a user action (such as the destination, value, and calldata). It finds the corresponding policy rule, generates a ZK proof of compliance, and can optionally send a transaction to an on-chain verifier module to execute the action.

## Configuration Files

The security policy is defined across three JSON files:

*   `policy.json`: Contains the list of all `PolicyLine` rules. Each rule has an `id` and defines what is allowed for a specific type of transaction.
*   `groups.json`: Defines lists of addresses that can be referenced by policies. This is useful for managing collections of related accounts, like team members or governance signers.
*   `allowlists.json`: Defines lists of addresses for approved on-chain contracts, such as trusted DEXs, lending protocols, or specific tokens.

## How to Run the Prover

You can run the prover from the `risc0` directory using a `cargo run` command. You must provide all the necessary details for the transaction you wish to prove.

### Generic Command Structure

```bash
cargo run --example prover -- \
    --policy-file examples/policy.json \
    --groups-file examples/groups.json \
    --allowlists-file examples/allowlists.json \
    --rule-id <RULE_ID> \
    --from <FROM_ADDRESS> \
    --to <TO_ADDRESS> \
    --value <VALUE_IN_WEI> \
    --data <HEX_CALLDATA> \
    -- nonce <NONCE> \
    --private-key <SIGNER_PRIVATE_KEY> \
    --verify-onchain
```

### Arguments

*   `--rule-id`: The `id` of the policy line in `policy.json` that you are proving against.
*   `--from`: The origin address of the transaction
*   `--to`: The destination address (`to`) of the transaction.
*   `--value`: The amount of native currency (e.g., Wei for ETH) to send. Use `0` for contract calls that don't transfer native value.
*   `--data`: The hexadecimal calldata for the transaction. For an ERC20 transfer, this would be the `transfer(address,uint256)` call data. For a simple contract call, it would be the function selector.
*   `--nonce`: The nonce of the wallet performing the action.
*   `--private-key`: The private key of the signer required by the policy rule. This key is used to sign the user action.
*   `--verify-onchain`: (Optional) If included, the prover will attempt to send a transaction to the on-chain `ZKGuardSafeModule` to verify the proof and execute the action.

### On-Chain Verification Setup

To use the `--verify-onchain` flag, you must have a `.env` file in the `risc0` directory with the following variables:

```
WALLET_PRIV_KEY="<PRIVATE_KEY_FOR_ONCHAIN_TX_SENDER>"
ETH_RPC_URL="<YOUR_ETHEREUM_RPC_URL>"
MODULE_ADDRESS="<DEPLOYED_ZKGUARD_MODULE_ADDRESS>"
SAFE_ADDRESS="<YOUR_GNOIS_SAFE_ADDRESS>"
```

---

## Example Scenarios

Here are some examples based on the rules defined in `policy.json`.

### 1. Contributor Payments (Rule 2)

This rule allows sending up to 5,000 USDC to a wallet in the `TeamWallets` group.

*   **Action**: Transfer 5,000 USDC (`5000000000` in token units) to `0x111...111`.
*   **Calldata**: An ERC20 `transfer` call to the USDC contract (`0xA0b...B48`).

```bash
cargo run --example prover -- \
    --policy-file examples/policy.json \
    --groups-file examples/groups.json \
    --allowlists-file examples/allowlists.json \
    --rule-id 2 \
    --from 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
    --to 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 \
    --value 0 \
    --nonce 0 \
    --data a9059cbb0000000000000000000000001111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000012a05f200 \
    --private-keys 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

### 2. DeFi Swaps on Approved DEXs (Rule 3)

This rule permits making a generic contract call to a DEX in the `ApprovedDEXs` allowlist.

*   **Action**: Call a function with selector `0xddc4d724` (hash of "test()") on the approved DEX at `0x333...333`.

```bash
cargo run --example prover -- \
    --policy-file examples/policy.json \
    --groups-file examples/groups.json \
    --allowlists-file examples/allowlists.json \
    --rule-id 3 \
    --from 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
    --to 0x3333333333333333333333333333333333333333 \
    --value 0 \
    --nonce 0 \
    --data ddc4d724 \
    --private-keys 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

### 3. Function-Level Controls for DEX Swaps (Rule 7)

This rule restricts calls to an approved DEX to a *specific* function (`0x7ff36ab5`).

*   **Action**: Call the `swapExactETHForTokens` function (selector `0x7ff36ab5`) on the approved DEX.

```bash
cargo run --example prover -- \
    --policy-file examples/policy.json \
    --groups-file examples/groups.json \
    --allowlists-file examples/allowlists.json \
    --rule-id 7 \
    --from 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
    --to 0x3333333333333333333333333333333333333333 \
    --value 0 \
    --nonce 0 \
    --data 7ff36ab5 \
    --private-keys 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80
```

### 4. Advanced Signer Policies (Rule 8)

This rule requires a 2-of-2 signature from the `GovernanceSigners` group.

```bash
cargo run --example prover -- \
    --policy-file examples/policy.json \
    --groups-file examples/groups.json \
    --allowlists-file examples/allowlists.json \
    --rule-id 8 \
    --from 0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266 \
    --to 0x3333333333333333333333333333333333333333 \
    --value 0 \
    --nonce 0 \
    --data 7ff36ab5 \
    --private-keys 0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d
```