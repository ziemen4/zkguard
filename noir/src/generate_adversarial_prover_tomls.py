#!/usr/bin/env python3
"""Generate witnesses for policy-soundness regressions that must be rejected."""

import argparse
import copy
import json
from pathlib import Path
from typing import Any

import toml

from generate_prover_toml import (
    ASSET_PATTERN_EXACT,
    DEST_PATTERN_EXACT,
    DUMMY_PRIV_B,
    SIGNER_PATTERN_ANY,
    digest_for_user_action,
    sign_digest,
    write_toml,
)
from generate_shared_prover_toml import build_rule, build_user_action_and_ctx


def load_shared(shared_root: Path) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], dict[int, Any]]:
    with open(shared_root / "examples" / "scenarios.json", encoding="utf-8") as f:
        scenarios = json.load(f)
    with open(shared_root / "config" / "groups.json", encoding="utf-8") as f:
        groups = json.load(f)
    with open(shared_root / "config" / "allowlists.json", encoding="utf-8") as f:
        allowlists = json.load(f)
    with open(shared_root / "config" / "policy.json", encoding="utf-8") as f:
        rules = {int(rule["id"]): rule for rule in json.load(f)}
    return scenarios, groups, allowlists, rules


def build_case(
    name: str,
    scenarios: dict[str, Any],
    groups: dict[str, Any],
    allowlists: dict[str, Any],
    rules: dict[int, Any],
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[str]]:
    scenario = scenarios[name]
    action, context = build_user_action_and_ctx(scenario, groups, allowlists)
    rule = build_rule(copy.deepcopy(rules[int(scenario["rule_id"])]))
    return action, rule, context, scenario["private_keys"]


def resign(action: dict[str, Any], context: dict[str, Any], private_keys: list[str]) -> None:
    digest = digest_for_user_action(
        action["from"], action["to"], action["value"], action["data"], action["data_len"]
    )
    signatures: list[bytes] = []
    pubkeys_x: list[bytes] = []
    pubkeys_y: list[bytes] = []
    for key in private_keys:
        signature, pubkey_x, pubkey_y, _ = sign_digest(
            bytes.fromhex(key.removeprefix("0x")), digest
        )
        signatures.append(signature)
        pubkeys_x.append(pubkey_x)
        pubkeys_y.append(pubkey_y)
    action["_digest"] = digest
    action["signatures"] = signatures
    action["signature_count"] = len(signatures)
    context["signer_pubkeys_x"] = pubkeys_x
    context["signer_pubkeys_y"] = pubkeys_y


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    parser = argparse.ArgumentParser()
    parser.add_argument("--shared-root", type=Path, default=script_dir.parent.parent / "shared")
    parser.add_argument("--out-dir", type=Path, default=script_dir.parent)
    args = parser.parse_args()
    args.out_dir.mkdir(parents=True, exist_ok=True)

    scenarios, groups, allowlists, rules = load_shared(args.shared_root)
    cases: dict[str, tuple[dict[str, Any], dict[str, Any], dict[str, Any]]] = {}

    action, rule, context, _ = build_case(
        "advanced_signer_policies", scenarios, groups, allowlists, rules
    )
    action["signatures"][1] = action["signatures"][0]
    context["signer_pubkeys_x"][1] = context["signer_pubkeys_x"][0]
    context["signer_pubkeys_y"][1] = context["signer_pubkeys_y"][0]
    cases["duplicate_threshold_signer"] = (action, rule, context)

    action, rule, context, _ = build_case(
        "contributor_payments", scenarios, groups, allowlists, rules
    )
    rule["signer"] = {
        "kind": SIGNER_PATTERN_ANY,
        "address": b"\x00" * 20,
        "group_name_hash_bytes": b"\x00" * 32,
        "threshold": 0,
    }
    # Keep the real action signature but pair it with an unrelated public key.
    _, pubkey_x, pubkey_y, _ = sign_digest(DUMMY_PRIV_B, b"\x01" * 32)
    context["signer_pubkeys_x"] = [pubkey_x]
    context["signer_pubkeys_y"] = [pubkey_y]
    cases["unverified_any_signer"] = (action, rule, context)

    action, rule, context, keys = build_case(
        "contributor_payments", scenarios, groups, allowlists, rules
    )
    action["data_len"] = 0
    resign(action, context, keys)
    cases["uncommitted_erc20_calldata"] = (action, rule, context)

    action, rule, context, keys = build_case(
        "contributor_payments", scenarios, groups, allowlists, rules
    )
    action["value"] = 1
    resign(action, context, keys)
    rule["destination"] = {
        "kind": DEST_PATTERN_EXACT,
        "name_hash_bytes": b"\x00" * 32,
        "address": action["to"],
    }
    rule["asset"] = {"kind": ASSET_PATTERN_EXACT, "address": b"\x00" * 20}
    rule["has_amount_max"] = False
    rule["amount_max"] = 0
    cases["native_value_with_calldata"] = (action, rule, context)

    action, rule, context, keys = build_case(
        "function_level_controls", scenarios, groups, allowlists, rules
    )
    action["data_len"] = 0
    resign(action, context, keys)
    cases["uncommitted_function_selector"] = (action, rule, context)

    action, rule, context, keys = build_case(
        "contributor_payments", scenarios, groups, allowlists, rules
    )
    rule["has_amount_max"] = True
    rule["amount_max"] = 1
    field_modulus = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    data = bytearray(action["data"])
    data[36:68] = (field_modulus + 1).to_bytes(32, "big")
    action["data"] = bytes(data)
    resign(action, context, keys)
    cases["erc20_amount_above_u128"] = (action, rule, context)

    for name, (action, rule, context) in cases.items():
        write_toml(action, rule, context, str(args.out_dir / f"Prover_adversarial_{name}.toml"))

    # Exercise real depth-three membership against the registered shared-policy
    # root. These mutations must fail before transaction-policy evaluation.
    action, rule, context, _ = build_case(
        "contributor_payments", scenarios, groups, allowlists, rules
    )
    ordered_policy = [build_rule(copy.deepcopy(raw_rule)) for raw_rule in rules.values()]
    selected_index = next(
        i
        for i, candidate in enumerate(ordered_policy)
        if candidate["id"] == rule["id"]
    )
    base_path = args.out_dir / "Prover_adversarial_wrong_merkle_sibling.toml"
    write_toml(
        action,
        rule,
        context,
        str(base_path),
        policy_rules=ordered_policy,
        selected_rule_index=selected_index,
    )
    base = toml.load(base_path)

    mutated_witnesses = {}
    witness = copy.deepcopy(base)
    witness["policy_merkle_path"]["siblings"][0] = hex(
        int(witness["policy_merkle_path"]["siblings"][0], 16) + 1
    )
    mutated_witnesses["wrong_merkle_sibling"] = witness

    witness = copy.deepcopy(base)
    witness["policy_merkle_path"]["leaf_index"] ^= 1
    mutated_witnesses["wrong_merkle_index"] = witness

    witness = copy.deepcopy(base)
    witness["policy_merkle_path"]["depth"] = 9
    mutated_witnesses["excessive_merkle_depth"] = witness

    witness = copy.deepcopy(base)
    witness["registered_policy_root"] = hex(
        int(witness["registered_policy_root"], 16) + 1
    )
    mutated_witnesses["wrong_registered_root"] = witness

    for name, witness in mutated_witnesses.items():
        output_path = args.out_dir / f"Prover_adversarial_{name}.toml"
        with open(output_path, "w", encoding="utf-8") as output:
            toml.dump(witness, output)

    mutated_rule = copy.deepcopy(rule)
    mutated_rule["id"] += 100
    write_toml(
        action,
        mutated_rule,
        context,
        str(args.out_dir / "Prover_adversarial_mutated_rule_id.toml"),
        policy_rules=ordered_policy,
        selected_rule_index=selected_index,
    )


if __name__ == "__main__":
    main()
