# ZKGuard + Ligero

This directory provides a Ligero proving path for the ZKGuard `risc0/examples` scenarios.

## Scope

The Ligero guest checks:

1. Policy rule membership via Merkle path against a policy root.
2. Policy compliance for:
   - `Transfer` and `ContractCall`
   - destination modes: `Any`, `Exact`, group/allowlist membership
   - signer modes: `Any`, `Exact`, group membership, threshold
   - asset matching
   - `amount_max`
   - optional function selector for contract calls

## Layout

- `common/`: shared JSON policy types and parsing helpers.
- `guest/`: Ligero WASM policy-check guest.
- `host/`: native input generator (`zkguard-ligero-inputs`).
- `examples/run_risc0_examples.sh`: runs all documented `risc0/examples/README.md` scenarios end-to-end.
- `../shared/config/*.json`: canonical policy/groups/allowlists used by all proving systems.
- `../shared/examples/scenarios.json`: canonical example actions/keys used by all proving systems.

## Build

```bash
cd ligero/guest
cargo build --target wasm32-wasip1 --release

cd ../host
cargo build --release
```

## Run All Examples

```bash
cd ligero/examples
./run_risc0_examples.sh
```

This generates per-scenario artifacts under `ligero/proof/examples/<scenario_name>/`, including:

- `ligero/proof/examples/contributor_payments/`
- `ligero/proof/examples/defi_swaps/`
- `ligero/proof/examples/supply_lending/`
- `ligero/proof/examples/interact_dapps/`
- `ligero/proof/examples/amount_limits/`
- `ligero/proof/examples/function_level_controls/`
- `ligero/proof/examples/advanced_signer_policies/`

Each scenario directory contains:

- `prover_input.json`
- `verifier_input.json`
- `prover.log`
- `verifier.log`

Expected successful lines in each case:

- `Final prove result:                  true`
- `Final Verify Result:                 true`
