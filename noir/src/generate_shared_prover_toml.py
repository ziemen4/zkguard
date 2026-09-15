#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
from typing import Any

from generate_prover_toml import (
    ASSET_PATTERN_ANY,
    ASSET_PATTERN_EXACT,
    DEST_PATTERN_ALLOWLIST,
    DEST_PATTERN_ANY,
    DEST_PATTERN_EXACT,
    DEST_PATTERN_GROUP,
    MAX_SIGNATURES,
    SIGNER_PATTERN_ANY,
    SIGNER_PATTERN_EXACT,
    SIGNER_PATTERN_GROUP,
    SIGNER_PATTERN_THRESHOLD,
    TX_TYPE_CONTRACT_CALL,
    TX_TYPE_TRANSFER,
    digest_for_user_action,
    keccak256,
    sign_digest,
    write_toml,
)


def parse_addr(hex_str: str) -> bytes:
    return bytes.fromhex(hex_str.removeprefix("0x"))


def parse_selector(selector_hex: str | None) -> bytes:
    if selector_hex is None:
        return b"\x00" * 4
    raw = bytes.fromhex(selector_hex.removeprefix("0x"))
    if len(raw) != 4:
        raise ValueError(f"function selector must be 4 bytes, got {len(raw)}")
    return raw


def build_destination(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        if raw != "Any":
            raise ValueError(f"unsupported destination string variant: {raw}")
        return {"kind": DEST_PATTERN_ANY, "name_hash_bytes": b"\x00" * 32, "address": b"\x00" * 20}

    if not isinstance(raw, dict) or len(raw) != 1:
        raise ValueError(f"invalid destination pattern: {raw}")
    key, value = next(iter(raw.items()))

    if key == "Exact":
        return {"kind": DEST_PATTERN_EXACT, "name_hash_bytes": b"\x00" * 32, "address": parse_addr(value)}
    if key == "Group":
        return {"kind": DEST_PATTERN_GROUP, "name_hash_bytes": keccak256(value.encode()), "address": b"\x00" * 20}
    if key == "Allowlist":
        return {
            "kind": DEST_PATTERN_ALLOWLIST,
            "name_hash_bytes": keccak256(value.encode()),
            "address": b"\x00" * 20,
        }

    raise ValueError(f"unsupported destination pattern key: {key}")


def build_signer(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        if raw != "Any":
            raise ValueError(f"unsupported signer string variant: {raw}")
        return {
            "kind": SIGNER_PATTERN_ANY,
            "address": b"\x00" * 20,
            "group_name_hash_bytes": b"\x00" * 32,
            "threshold": 0,
        }

    if not isinstance(raw, dict) or len(raw) != 1:
        raise ValueError(f"invalid signer pattern: {raw}")
    key, value = next(iter(raw.items()))

    if key == "Exact":
        return {
            "kind": SIGNER_PATTERN_EXACT,
            "address": parse_addr(value),
            "group_name_hash_bytes": b"\x00" * 32,
            "threshold": 0,
        }
    if key == "Group":
        return {
            "kind": SIGNER_PATTERN_GROUP,
            "address": b"\x00" * 20,
            "group_name_hash_bytes": keccak256(value.encode()),
            "threshold": 0,
        }
    if key == "Threshold":
        group_name = value["group"]
        threshold = int(value["threshold"])
        return {
            "kind": SIGNER_PATTERN_THRESHOLD,
            "address": b"\x00" * 20,
            "group_name_hash_bytes": keccak256(group_name.encode()),
            "threshold": threshold,
        }

    raise ValueError(f"unsupported signer pattern key: {key}")


def build_asset(raw: Any) -> dict[str, Any]:
    if isinstance(raw, str):
        if raw != "Any":
            raise ValueError(f"unsupported asset string variant: {raw}")
        return {"kind": ASSET_PATTERN_ANY, "address": b"\x00" * 20}

    if not isinstance(raw, dict) or len(raw) != 1:
        raise ValueError(f"invalid asset pattern: {raw}")
    key, value = next(iter(raw.items()))

    if key == "Exact":
        return {"kind": ASSET_PATTERN_EXACT, "address": parse_addr(value)}

    raise ValueError(f"unsupported asset pattern key: {key}")


def build_rule(raw_rule: dict[str, Any]) -> dict[str, Any]:
    tx_type = raw_rule["tx_type"]
    if tx_type == "Transfer":
        tx_tag = TX_TYPE_TRANSFER
    elif tx_type == "ContractCall":
        tx_tag = TX_TYPE_CONTRACT_CALL
    else:
        raise ValueError(f"unsupported tx_type: {tx_type}")

    amount_max = raw_rule.get("amount_max")
    selector_hex = raw_rule.get("function_selector")

    return {
        "id": int(raw_rule["id"]),
        "tx_type": tx_tag,
        "destination": build_destination(raw_rule["destination"]),
        "signer": build_signer(raw_rule["signer"]),
        "asset": build_asset(raw_rule["asset"]),
        "has_amount_max": amount_max is not None,
        "amount_max": int(amount_max) if amount_max is not None else 0,
        "has_function_selector": selector_hex is not None,
        "function_selector": parse_selector(selector_hex),
    }


def build_ctx(groups: dict[str, list[str]], allowlists: dict[str, list[str]], pubkeys_xy: list[tuple[bytes, bytes]]) -> dict[str, Any]:
    group_entries: list[tuple[bytes, bytes]] = []
    for name in sorted(groups.keys()):
        h = keccak256(name.encode())
        for addr in groups[name]:
            group_entries.append((parse_addr(addr), h))

    allow_entries: list[tuple[bytes, bytes]] = []
    for name in sorted(allowlists.keys()):
        h = keccak256(name.encode())
        for addr in allowlists[name]:
            allow_entries.append((parse_addr(addr), h))

    groups_bytes = [addr for addr, _ in group_entries][:MAX_SIGNATURES]
    group_hashes = [h for _, h in group_entries][:MAX_SIGNATURES]
    allow_bytes = [addr for addr, _ in allow_entries][:MAX_SIGNATURES]
    allow_hashes = [h for _, h in allow_entries][:MAX_SIGNATURES]

    while len(groups_bytes) < MAX_SIGNATURES:
        groups_bytes.append(b"\x00" * 20)
        group_hashes.append(b"\x00" * 32)
    while len(allow_bytes) < MAX_SIGNATURES:
        allow_bytes.append(b"\x00" * 20)
        allow_hashes.append(b"\x00" * 32)

    pkx = [x for x, _ in pubkeys_xy][:MAX_SIGNATURES]
    pky = [y for _, y in pubkeys_xy][:MAX_SIGNATURES]
    while len(pkx) < MAX_SIGNATURES:
        pkx.append(b"\x00" * 32)
        pky.append(b"\x00" * 32)

    return {
        "groups": groups_bytes,
        "group_name_hashes": group_hashes,
        "allowlists": allow_bytes,
        "allowlist_name_hashes": allow_hashes,
        "signer_pubkeys_x": pkx,
        "signer_pubkeys_y": pky,
    }


def build_user_action_and_ctx(scenario: dict[str, Any], groups: dict[str, list[str]], allowlists: dict[str, list[str]]) -> tuple[dict[str, Any], dict[str, Any]]:
    from_addr = parse_addr(scenario["from"])
    to_addr = parse_addr(scenario["to"])
    value = int(scenario["value"])
    data = bytes.fromhex(scenario["data"].removeprefix("0x"))
    data_len = len(data)

    digest = digest_for_user_action(from_addr, to_addr, value, data, data_len)

    signatures: list[bytes] = []
    pubkeys_xy: list[tuple[bytes, bytes]] = []
    for key in scenario["private_keys"]:
        sig, x, y, _ = sign_digest(bytes.fromhex(key.removeprefix("0x")), digest)
        signatures.append(sig)
        pubkeys_xy.append((x, y))

    user_action = {
        "from": from_addr,
        "to": to_addr,
        "value": value,
        "data": data,
        "data_len": data_len,
        "signatures": signatures,
        "signature_count": len(signatures),
        "_digest": digest,
    }
    ctx = build_ctx(groups, allowlists, pubkeys_xy)
    return user_action, ctx


def scenario_to_toml(
    scenario_name: str,
    scenarios: dict[str, Any],
    rules_by_id: dict[int, dict[str, Any]],
    ordered_rules: list[dict[str, Any]],
    groups: dict[str, list[str]],
    allowlists: dict[str, list[str]],
    out_path: Path,
) -> None:
    if scenario_name not in scenarios:
        raise KeyError(f"unknown scenario '{scenario_name}'")

    scenario = scenarios[scenario_name]
    rule_id = int(scenario["rule_id"])
    if rule_id not in rules_by_id:
        raise KeyError(f"rule id {rule_id} from scenario '{scenario_name}' not found in policy")

    user_action, ctx = build_user_action_and_ctx(scenario, groups, allowlists)
    built_rules = [build_rule(raw_rule) for raw_rule in ordered_rules]
    selected_index = next(
        i for i, candidate in enumerate(built_rules) if candidate["id"] == rule_id
    )
    rule = built_rules[selected_index]
    write_toml(
        user_action,
        rule,
        ctx,
        str(out_path),
        policy_rules=built_rules,
        selected_rule_index=selected_index,
    )


def main() -> None:
    script_dir = Path(__file__).resolve().parent
    default_shared = script_dir.parent.parent / "shared"

    parser = argparse.ArgumentParser(description="Generate Noir Prover.toml from shared zkguard config")
    parser.add_argument(
        "--scenario",
        default="contributor_payments",
        help="scenario name from shared/examples/scenarios.json or 'all'",
    )
    parser.add_argument("--shared-root", default=str(default_shared), help="path to shared directory")
    parser.add_argument("--out", default="Prover.toml", help="output path for single-scenario mode")
    args = parser.parse_args()

    shared_root = Path(args.shared_root)
    policy_path = shared_root / "config" / "policy.json"
    groups_path = shared_root / "config" / "groups.json"
    allowlists_path = shared_root / "config" / "allowlists.json"
    scenarios_path = shared_root / "examples" / "scenarios.json"

    with open(policy_path, "r", encoding="utf-8") as f:
        policy = json.load(f)
    with open(groups_path, "r", encoding="utf-8") as f:
        groups = json.load(f)
    with open(allowlists_path, "r", encoding="utf-8") as f:
        allowlists = json.load(f)
    with open(scenarios_path, "r", encoding="utf-8") as f:
        scenarios = json.load(f)

    rules_by_id = {int(rule["id"]): rule for rule in policy}

    if args.scenario == "all":
        for name in scenarios.keys():
            out_path = Path(f"Prover_{name}.toml")
            scenario_to_toml(name, scenarios, rules_by_id, policy, groups, allowlists, out_path)
            print(f"Generated {out_path}")
        return

    out_path = Path(args.out)
    scenario_to_toml(args.scenario, scenarios, rules_by_id, policy, groups, allowlists, out_path)
    print(f"Generated {out_path}")


if __name__ == "__main__":
    main()
