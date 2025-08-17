# DAO Security Policies for ZKGuard Examples

This directory contains a prover that demonstrates how to use ZKGuard to enforce a set of security policies for a fictional DAO. The examples below showcase various rules, from simple transfers to more complex, multi-signature contract calls.

To run any of the examples, use the following command from the `risc0` directory, replacing `<example_name>` with the name of the policy you want to test (e.g., `contributor_payments`):

```bash
cargo run --example dao_prover -- --example <example_name>
```

## Predefined Groups & Allow-lists

To protect our treasury and operations, we've defined several Groups and Allow-lists that form the backbone of our policy set.

### Groups:

*   **TeamWallets**: A list of verified wallet addresses for core contributors and recurring payroll.
*   **GovernanceSigners**: A list of addresses belonging to the DAO's most trusted members, who can approve high-risk operations.

### Allow-lists:

*   **ApprovedDEXs**: A list of router contract addresses for trusted Decentralized Exchanges (e.g., Uniswap v3 Router).
*   **ApprovedLendingProtocols**: A list of entry-point contract addresses for trusted lending protocols (e.g., Aave Pool).
*   **ApprovedStablecoins**: A list of token addresses for reputable stablecoins (e.g., USDC, DAI).
*   **ApprovedBlueChipAssets**: A list of token addresses for established, high-liquidity assets (e.g., WETH, WBTC).

---

## Policy Set

Here are the specific rules (`PolicyLine` objects) established in the examples. Our Safe's address is the primary signer for most transactions it executes.

### 1. Contributor Payments (`contributor_payments`)

This rule allows us to pay our team members in stablecoins.

*   **tx_type**: `Transfer`
*   **destination**: `Group(TeamWallets)`
*   **signer**: `Exact(our_dao_safe_address)`
*   **asset**: `Allowlist(ApprovedStablecoins)`
*   **action**: `Allow`

### 2. DeFi Swaps on Approved DEXs (`defi_swaps`)

This rule permits the DAO to swap assets on trusted exchanges, which is essential for rebalancing our treasury.

*   **tx_type**: `ContractCall`
*   **destination**: `Allowlist(ApprovedDEXs)`
*   **signer**: `Exact(our_dao_safe_address)`
*   **asset**: `Any` (The asset being sent is validated by the DEX contract interaction itself)
*   **action**: `Allow`

### 3. Supplying Assets to Lending Protocols (`supply_lending`)

This rule allows us to earn yield on our treasury's holdings by supplying approved assets to major lending protocols.

*   **tx_type**: `Transfer`
*   **destination**: `Allowlist(ApprovedLendingProtocols)`
*   **signer**: `Exact(our_dao_safe_address)`
*   **asset**: `Allowlist(ApprovedBlueChipAssets)`
*   **action**: `Allow`

### 4. Interacting with Approved dApps (`interact_dapps`)

A more general rule to interact with any approved DeFi protocol. This allows for function calls beyond simple transfers.

*   **tx_type**: `ContractCall`
*   **destination**: `Allowlist(ApprovedLendingProtocols)`
*   **signer**: `Exact(our_dao_safe_address)`
*   **asset**: `Any`
*   **action**: `Allow`

### 5. Amount Limits for Contributor Payments (`amount_limits`)

This rule enhances contributor payments by adding a maximum amount, preventing accidental over-payments.

*   **tx_type**: `Transfer`
*   **destination**: `Group(TeamWallets)`
*   **signer**: `Exact(our_dao_safe_address)`
*   **asset**: `Allowlist(ApprovedStablecoins)`
*   **amount_max**: `10,000 USDC`
*   **action**: `Allow`

### 6. Function-Level Controls for DEX Swaps (`function_level_controls`)

This rule restricts contract calls to a specific function, allowing only exact-input swaps and preventing other, potentially riskier, functions from being called on a DEX.

*   **tx_type**: `ContractCall`
*   **destination**: `Allowlist(ApprovedDEXs)`
*   **signer**: `Exact(our_dao_safe_address)`
*   **asset**: `Any`
*   **function_selector**: `0x7ff36ab5` (swapExactETHForTokens)
*   **action**: `Allow`

### 7. Advanced Signer Policies for High-Value Operations (`advanced_signer_policies`)

This rule protects high-value operations by requiring a threshold of signatures from the DAO's most trusted members.

*   **tx_type**: `ContractCall`
*   **destination**: `Allowlist(ApprovedDEXs)`
*   **signer**: `Threshold { group: "GovernanceSigners", threshold: 2 }`
*   **asset**: `Any`
*   **action**: `Allow`
