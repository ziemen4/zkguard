# ZKGuard: Noir Implementation

This directory contains a Noir-based zk circuit that implements the ZKGuard policy engine. It validates a user action against a committed policy rule and enforces the rule’s constraints (destination, signer policy, asset, amount limits, optional function selectors). Public outputs commit to the action and reference data so on-chain or off-chain verifiers can check consistency.

## 🏛️ Architecture

- Policy membership: The circuit hashes the provided `PolicyLine` and each Merkle node with Poseidon2, asserts that the result equals the public `registered_policy_root`, and exposes the same value as `policy_hash`. The consuming verifier must pin `registered_policy_root` to the root authorized for the account before accepting a proof.
- Policy compliance: The circuit classifies the `UserAction` as either a native/ERC-20 transfer or a contract call, then enforces rule constraints on type, destination pattern (any, group, allowlist), signer policy (any, exact, group, threshold), asset pattern, and optional amount/function selector checks. Every signer pattern requires a verified signature, and threshold rules count distinct signer addresses rather than signature slots.
- Cryptography:
  - Poseidon2: Policy-leaf hashing and Merkle membership.
  - Legacy Keccak-256: Ethereum-specific hashing (action digest, pubkey-to-address derivation, set hashing for groups/allowlists).
  - ECDSA secp256k1: Signature verification via Noir’s `std::ecdsa_secp256k1::verify_signature`.

Key sources:
- Circuit entrypoint: `src/main.nr`
- Types and constants: `src/policy.nr`
- Inputs generator: `src/generate_prover_toml.py` (see `src/README.md`)

## 📜 Inputs and Outputs

The circuit takes structured inputs (provided through `Prover.toml`) and returns public outputs for verification.

- Public outputs (`PublicOutputs`):
  - `call_hash`: Keccak-256 of the user action (`from || to || value(32) || data[:data_len]`).
  - `policy_hash`: The computed Poseidon2 policy Merkle root. It must equal the root registered by the verifier.
  - `groups_hash`, `allow_hash`: Keccak-256 commitments over the non-empty entries of groups and allowlists (address + name-hash pairs).

- Prover inputs (from `Prover.toml`):
  - `registered_policy_root`: The public policy root that the authorizer has registered. The circuit constrains the private rule and path to this value; the proof consumer must compare the public input with its own trusted value.
  - `rule`: The single `PolicyLine` allegedly allowing the action.
  - `user_action`: Destination, value, calldata, and one or more 64-byte ECDSA signatures encoded as `{r||s}`.
  - `ctx`: Groups, allowlists, and one pubkey `(x,y)` per signature slot used for signer checks.
  - `policy_merkle_path`: The selected rule's Poseidon2 membership witness. The circuit supports depths up to 8 (256 policy leaves). The shared-config generator builds a real path over every rule in `shared/config/policy.json`.

Noir verifies `(r,s)` against the supplied public key, so its input intentionally omits Ethereum's recovery byte `v`. The RISC Zero backend accepts 65-byte `{r||s||v}` signatures and validates recovery. When Noir slots are unused, do not zero-fill signatures or pubkeys. Use the provided generator to create valid-but-non-matching placeholders to avoid gadget warnings and ensure predictable behavior.

`src/policy_tree.py` is the canonical off-circuit tree builder. It preserves the JSON array order, pads the leaves to the next power of two with zero field elements, and emits siblings from leaf to root. `src/test_policy_tree.py` pins the current shared-policy root and tests paths on both sides of depth-one, depth-two, and depth-three trees. Changing policy semantics, rule order, leaf encoding, the Poseidon parameters, or any rule changes the root and requires updating the registered roots. Circuit changes also require regenerating the verification key.

An authorizer must combine proof verification with a comparison between the proof's public policy root and the root trusted for the account. The runner performs this check with `src/verify_public_policy_root.py` on Barretenberg's `public_inputs` before accepting the proof. Production authorizers must perform the equivalent comparison. The script's field indexes are tied to this circuit ABI and must be reviewed if public inputs are reordered.

Calldata is canonical: `data_len` must fit the fixed buffer, all bytes after it must be zero, and any selector or ERC-20 fields inspected by the circuit must fall within the committed prefix. The current action model also rejects nonzero native value combined with calldata. Native values, policy limits, and ERC-20 amounts are constrained to the shared `u128` policy domain.

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

- `nargo version = 1.0.0-beta.13`
- `noirc version = 1.0.0-beta.13+6e469c3004209a8b107e7707306e25c80a110fd6`
- `bb version = v0.87.0`
- Noir deps in `Nargo.toml` (pinned):
  - `keccak256` `v0.1.0`
  - `poseidon` `v0.2.6`
  - local `ecrecover-noir` path under `ecrecover`
  - local `noir-array-helpers` path under `noir-array-helpers`

Verify locally:

```bash
nargo --version
bb --version
```


If you change versions, re‑run compile/execute/prove/verify to confirm compatibility.

## Local Dependencies

This repo intentionally keeps two local Noir dependencies in this directory:

- `ecrecover`
- `noir-array-helpers`

They are here because the upstream dependency chain did not compile cleanly for the toolchain/version combination used to validate this project. In particular, the upstream `noir-array-helpers` code hit a bit-width mismatch in the shift expression used during compilation, and simply bumping `ecrecover-noir` was not enough to remove that failure.

Keeping these dependencies local gives this repo a clone-and-run path that is reproducible without ad hoc patching inside a package cache at build time. If upstream releases a compatible version later, these local copies can be removed and the dependencies can be switched back to upstream tags.

## 🚀 How to Run

Run these commands.

1) Generate inputs (Prover.toml)

Use the shared-config helper to build a consistent `Prover.toml` with safe signature placeholders and the chosen rule.

```bash
python src/generate_shared_prover_toml.py --scenario contributor_payments --out Prover.toml
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
python src/generate_shared_prover_toml.py --scenario contributor_payments --out Prover.toml

# 2-of-2 threshold signer example
python src/generate_shared_prover_toml.py --scenario advanced_signer_policies --out Prover.toml
```

To generate all shared scenarios:

```bash
python src/generate_shared_prover_toml.py --scenario all
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

The repository runner also executes adversarial witnesses covering duplicate threshold signers, invalid `Any` signatures, uncommitted calldata, mixed native value and calldata, overflowing ERC-20 amounts, uncommitted function selectors, corrupt Merkle siblings and indexes, excessive path depth, mismatched roots, and mutated rule IDs. Each witness must be rejected by the circuit.

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
