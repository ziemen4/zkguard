# Prover.toml Generator with Safe ECDSA Placeholders

This repository includes `generate_prover_toml.py`, a utility that creates `Prover.toml` inputs for our Noir circuit. It fixes a subtle but critical pitfall that can cause **builder warnings** and **verification failure** when unused signature slots are filled with zeros.

---

## Requirements

* **Python 3.10+**
* **Packages:**

  * `coincurve` (secp256k1 signing)
  * `eth-hash` (for `keccak`)
  * `toml`

Install:

```bash
python -m pip install coincurve eth-hash toml
```

---

## How the script works

### 1) Computes the action digest

We construct a `digest` from the user action:

```
keccak( to[20] || value[32] || data[:data_len] )
```

This must match the digest used inside the circuit.

### 2) Signs with the *real* key for active slots

For the active signer(s), we sign `digest` with the provided private key(s). We also:

* **Normalize to low‑s** (ensures `s ≤ n/2`).
* Keep `sig65 = r(32) || s(32) || v(1)`; the circuit will derive `sig64` as needed.
* Extract the uncompressed pubkey `(px,py)` for the active signer entry in `ctx`.

### 3) Generates **safe placeholders** for inactive slots

For **each scenario’s digest**, we generate a placeholder tuple:

* **Signature** = sign(`digest`) with **DummyKey A**, low‑s normalized.
* **Public key** = `(px,py)` from **DummyKey B**.
  Because A ≠ B, `verify_signature(pk_B, sig_A, digest)` returns `false` without tripping the gadget.

We then:

* Fill all **unused signatures** with the placeholder signature (65 bytes).
* Replace **zeroed pubkeys** in `ctx.signer_pubkeys_x/y` with the placeholder `(px_B, py_B)`.

### 4) Pads & formats to TOML

* `data` → padded to `MAX_CALLDATA_SIZE`.
* `signatures` → padded to `MAX_SIGNATURES` with placeholders.
* `signer_pubkeys_x/y` → padded to `MAX_SIGNATURES` with placeholder keys.
* 20‑byte addresses and 32‑byte fields are hex‑formatted as `["0x..", ...]`.

---

## Running the generator

Single scenario:

```bash
python generate_prover_toml.py --scenario defi_swaps --key <hex_priv_no_0x> --out Prover.toml
```

All scenarios (files `Prover_<name>.toml`):

```bash
python generate_prover_toml.py --scenario all --key <hex_priv_no_0x> --key2 <hex_priv_no_0x>
```

Available scenarios:

* `contributor_payments`
* `defi_swaps`
* `supply_lending`
* `interact_dapps`
* `amount_limits`
* `function_level_controls`
* `advanced_signer_policies` (uses `--key2`)

> Keys passed via `--key` / `--key2` are only used for **active slots**.

---

## End‑to‑end check

With `barretenberg v0.87.0` and `nargo 1.0.0‑beta.13`:

```bash
nargo execute

# produce proof
bb prove -b ./target/zkguard.json -w ./target/zkguard.gz --write_vk -o target

# verify
bb verify -p ./target/proof -k ./target/vk
```

---

## Customization

* **Dummy keys:** change `DUMMY_PRIV_A` and `DUMMY_PRIV_B` to any deterministic values you prefer. Keep them distinct to guarantee mismatch.
* **MAX constants:** ensure `MAX_CALLDATA_SIZE`, `MAX_SIGNATURES`, and `SIGNATURE_SIZE` match your circuit constants.
* **Digest format:** if you change how the circuit hashes the action, update `digest_for_user_action` accordingly.

---

## Version notes

* Tested with:

  * `barretenberg v0.87.0`
  * `nargo 1.0.0‑beta.13`
* If you upgrade, re‑validate the workflow and keep placeholders in place to avoid regressions.

---

## Security

* Dummy keys (A/B) are **not secrets** and exist only to create safe placeholders for inactive slots. Do **not** use them for real signing.

---

## Summary

* The root cause was evaluating `verify_signature` on **inactive** entries with **invalid zeroed data**.
* Supplying **valid‑but‑non‑matching** placeholders (low‑s signature from Dummy A, pubkey from Dummy B) ensures the ECDSA gadget always receives sane inputs and returns `false` cleanly for inactive slots.
* With these inputs, proving succeeds **without warnings** and verification passes.
