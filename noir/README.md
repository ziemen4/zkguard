# ZKGuard: Noir Implementation

This directory contains a Noir-based zk circuit that implements the ZKGuard policy engine. It validates a user action against a committed policy via a SHA-256 Merkle proof and enforces the rule’s constraints (destination, signer policy, asset, amount limits, optional function selectors). Public outputs commit to the action and reference data so on-chain or off-chain verifiers can check consistency.

## 🏛️ Architecture

- Merkle membership: The circuit recomputes the policy leaf from the provided `PolicyLine`, hashes it with SHA-256, and verifies inclusion against a public `policy_merkle_root` using a provided Merkle path.
- Policy compliance: The circuit classifies the `UserAction` as either a native/erc20 transfer or a contract call, then enforces rule constraints on type, destination pattern (any, group, allowlist), signer policy (any, exact, group, threshold), asset pattern, and optional amount/function selector checks.
- Cryptography:
  - SHA-256: Merkle leaf and node hashing.
  - Legacy Keccak-256: Ethereum-specific hashing (action digest, pubkey-to-address derivation, set hashing for groups/allowlists).
  - ECDSA secp256k1: Signature verification via Noir’s `std::ecdsa_secp256k1::verify_signature`.

Key sources:
- Circuit entrypoint: `src/main.nr`
- Types and constants: `src/policy.nr`
- Inputs generator: `src/generate_prover_toml.py` (see `src/README.md`)

## 📜 Inputs and Outputs

The circuit takes structured inputs (provided through `Prover.toml`) and returns public outputs for verification.

- Public outputs (`PublicOutputs`):
  - `call_hash`: Keccak-256 of the user action (`to || value(32) || data[:data_len]`).
  - `policy_hash`: Alias of `policy_merkle_root` (the committed policy root).
  - `groups_hash`, `allow_hash`: Keccak-256 commitments over the non-empty entries of groups and allowlists (address + name-hash pairs).

- Prover inputs (from `Prover.toml`):
  - `rule`: The single `PolicyLine` allegedly allowing the action.
  - `user_action`: Destination, value, calldata, and one or more 65-byte Ethereum signatures.
  - `ctx`: Groups, allowlists, and one pubkey `(x,y)` per signature slot used for signer checks.
  - `policy_merkle_root`, `policy_merkle_path`: Root and Merkle proof for the rule’s inclusion.

Note on signatures: The circuit converts `{r||s||v}` (65 bytes) into `{r||s}` to feed the verifier. When slots are unused, do not zero-fill signatures or pubkeys. Use the provided generator to create valid-but-non-matching placeholders to avoid gadget warnings and ensure predictable behavior.

## ⚙️ Prerequisites

- Noir toolchain installation [quickstart](https://noir-lang.org/docs/getting_started/quick_start)

```bash
# noir
curl -L https://raw.githubusercontent.com/noir-lang/noirup/refs/heads/main/install | bash

# barretenberg
curl -L https://raw.githubusercontent.com/AztecProtocol/aztec-packages/refs/heads/next/barretenberg/bbup/install | bash
bbup
```

- Python 3.10+ for input generation
  - `coincurve`, `eth-hash`, `toml` (see `requirements.txt`)

Example setup:

```bash
# Noir toolchain (follow Noir docs to install nargo and bb)
# https://noir-lang.org/ — ensure versions roughly match above

# Python deps (coincurve has a native dependency; use a working toolchain)
python -m pip install -r requirements.txt coincurve
```

## 📦 Versions

Tested toolchain and crate versions for this repo:

- `nargo 1.0.0-beta.13`
- `barretenberg (bb) v0.87.0`
- Noir deps in `Nargo.toml` (pinned):
  - `keccak256` `v0.1.0`
  - `sha256` `v0.2.1`
  - `ecrecover-noir` `v1.0.0`

Verify locally:

```bash
nargo --version
bb --version
```

If you change versions, re‑run compile/execute/prove/verify to confirm compatibility.

## 🚀 How to Run

Run these commands.

1) Generate inputs (Prover.toml)

Use the helper to build a consistent `Prover.toml` with safe placeholders and a Merkle singleton for the chosen rule.

```bash
python src/generate_prover_toml.py --scenario contributor_payments --key <hex_priv_no_0x> --out Prover.toml
```

Available scenarios:
- `contributor_payments`
- `defi_swaps`
- `supply_lending`
- `interact_dapps`
- `amount_limits`
- `function_level_controls`
- `advanced_signer_policies` (requires `--key2` for 2-of-2 threshold)

Examples:

```bash
# 1-of-1 signer example
python src/generate_prover_toml.py --scenario contributor_payments --key <hex> --out Prover.toml

# 2-of-2 threshold signer example
python src/generate_prover_toml.py --scenario advanced_signer_policies --key <hex1> --key2 <hex2> --out Prover.toml
```

2) Compile and execute the circuit

```bash
nargo compile     # produces ./target/zkguard.json
nargo execute     # consumes Prover.toml and writes ./target/zkguard.gz
```

3) Prove and verify with Barretenberg

```bash
bb prove -b ./target/zkguard.json -w ./target/zkguard.gz --write_vk -o target
bb verify -p ./target/proof -k ./target/vk
```

If you only want to check logic (no proof), `nargo execute` is sufficient.

## 🧩 Policy Model (brief)

Patterns mirror the other implementations but are encoded as fixed-size Noir structs with constants in `auth-policy/noir/src/policy.nr`.

- `TxType`: `Transfer` or `ContractCall`.
- `DestinationPattern`: `Any`, `Group(name_hash)`, `Allowlist(name_hash)`.
- `SignerPattern`: `Any`, `Exact(address)`, `Group(name_hash)`, `Threshold { group_name_hash, threshold }`.
- `AssetPattern`: `Any` or `Exact(address)`.
- Optional constraints: `amount_max` (transfers) and a 4-byte `function_selector` (contract calls).

The circuit exports constants like `MAX_CALLDATA_SIZE`, `MAX_SIGNATURES`, and `SIGNATURE_SIZE`. Keep these in sync with the generator script.

## 📂 Files

- Circuit: `auth-policy/noir/src/main.nr`
- Types/constants: `auth-policy/noir/src/policy.nr`
- Input generator + scenarios: `auth-policy/noir/src/generate_prover_toml.py` (details: `auth-policy/noir/src/README.md`)
- Project manifest: `auth-policy/noir/Nargo.toml`
- Example input: `auth-policy/noir/Prover.toml`

## 🔎 Tips & Notes

- Dependencies in `Nargo.toml` use Git sources; ensure your environment can fetch them when compiling.
- Placeholder handling: The generator fills unused signature slots and zero pubkeys with valid-but-non-matching data to avoid warnings from the ECDSA gadget. Prefer using it over hand-editing `Prover.toml`.
- Version updates: If you upgrade `nargo`/`bb`, re-run the flow (`compile`, `execute`, `prove`, `verify`) to validate compatibility.
