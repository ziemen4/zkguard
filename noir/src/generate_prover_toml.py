# generate_prover_toml.py
import argparse
import os
import toml
from eth_hash.auto import keccak
from coincurve import PrivateKey

# ---- Must match your Noir constants ----
MAX_CALLDATA_SIZE = 256
MAX_SIGNATURES = 5
SIGNATURE_SIZE = 65

# tx_type: infer from your current setup (you used 0 for Transfer before)
TX_TYPE_TRANSFER = 0
TX_TYPE_CONTRACT_CALL = 1

# pattern kinds (common mapping)
DEST_PATTERN_ANY = 0
DEST_PATTERN_GROUP = 1
DEST_PATTERN_ALLOWLIST = 2

SIGNER_PATTERN_ANY = 0
SIGNER_PATTERN_EXACT = 1
SIGNER_PATTERN_GROUP = 2
SIGNER_PATTERN_THRESHOLD = 3

ASSET_PATTERN_ANY = 0
ASSET_PATTERN_EXACT = 1

BN254_SCALAR_MODULUS = int(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
)

# ---- Helpers ----
def keccak256(b: bytes) -> bytes:
    return keccak(b)

def bytes32_to_field_hex(b: bytes) -> str:
    v = int.from_bytes(b, "big") % BN254_SCALAR_MODULUS
    return f"0x{v:064x}"

def format_hex_array(
    data_bytes: bytes,
    *,
    pad_to: int | None = None,
    pad_byte: int = 0x00,
    pad_side: str = "right",
) -> list[str]:
    b = data_bytes
    if pad_to is not None:
        if len(b) > pad_to:
            b = b[:pad_to]
        elif len(b) < pad_to:
            pad = bytes([pad_byte]) * (pad_to - len(b))
            b = (pad + b) if pad_side == "left" else (b + pad)
    return [f"0x{byte:02x}" for byte in b]

def pad_list(lst, length, filler):
    return lst[:length] + [filler] * max(0, length - len(lst))

def u256_be(n: int) -> bytes:
    return n.to_bytes(32, "big")

def eth_addr_from_xy(x: bytes, y: bytes) -> bytes:
    return keccak(x + y)[12:]

def digest_for_user_action(to20: bytes, value_u256: int, data: bytes, data_len: int) -> bytes:
    buf = bytearray()
    buf += to20
    buf += u256_be(value_u256)
    buf += data[:data_len]
    return keccak(bytes(buf))

def sign_digest(privkey_bytes: bytes, digest32: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    pk = PrivateKey(privkey_bytes)
    sig65 = pk.sign_recoverable(digest32, hasher=None)
    pub_uncompressed = pk.public_key.format(compressed=False)  # 0x04||X||Y
    x, y = pub_uncompressed[1:33], pub_uncompressed[33:65]
    addr = eth_addr_from_xy(x, y)
    return sig65, x, y, addr

def write_toml(user_action, rule, ctx, out_path: str):
    data_padded = user_action["data"].ljust(MAX_CALLDATA_SIZE, b"\x00")
    sigs = pad_list(user_action["signatures"], MAX_SIGNATURES, b"\x00" * SIGNATURE_SIZE)

    toml_data = {
        "user_action": {
            "to": format_hex_array(user_action["to"], pad_to=20),
            "value": user_action["value"],
            "data": format_hex_array(data_padded, pad_to=MAX_CALLDATA_SIZE),
            "data_len": user_action["data_len"],
            "signatures": [format_hex_array(s, pad_to=SIGNATURE_SIZE) for s in sigs],
            "signature_count": user_action["signature_count"],
        },
        "rule": {
            "id": rule["id"],
            "tx_type": rule["tx_type"],
            "destination": {
                "kind": rule["destination"]["kind"],
                "name_hash": bytes32_to_field_hex(rule["destination"]["name_hash_bytes"]),
            },
            "signer": {
                "kind": rule["signer"]["kind"],
                "address": format_hex_array(rule["signer"]["address"], pad_to=20),
                "group_name_hash": bytes32_to_field_hex(rule["signer"]["group_name_hash_bytes"]),
                "threshold": rule["signer"]["threshold"],
            },
            "asset": {
                "kind": rule["asset"]["kind"],
                "address": format_hex_array(rule["asset"]["address"], pad_to=20),
            },
            "has_amount_max": rule["has_amount_max"],
            "amount_max": rule["amount_max"],
            "has_function_selector": rule["has_function_selector"],
            "function_selector": format_hex_array(rule["function_selector"], pad_to=4),
        },
        "ctx": {
            "groups": [format_hex_array(g, pad_to=20) for g in ctx["groups"]],
            "group_name_hashes": [bytes32_to_field_hex(h) for h in ctx["group_name_hashes"]],
            "allowlists": [format_hex_array(a, pad_to=20) for a in ctx["allowlists"]],
            "allowlist_name_hashes": [bytes32_to_field_hex(h) for h in ctx["allowlist_name_hashes"]],
            "signer_pubkeys_x": [format_hex_array(pk, pad_to=32) for pk in ctx["signer_pubkeys_x"]],
            "signer_pubkeys_y": [format_hex_array(pk, pad_to=32) for pk in ctx["signer_pubkeys_y"]],
        },
    }
    with open(out_path, "w") as f:
        toml.dump(toml_data, f)
    print(f"✅ Wrote {out_path}")

# ---- Scenario 1 (kept): contributor_payments ----
def contributor_payments(privkey_hex: str):
    priv = bytes.fromhex(privkey_hex.removeprefix("0x"))

    team_wallet_1 = bytes.fromhex("1111111111111111111111111111111111111111")
    usdc          = bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    amount        = 5_000 * 10**6

    group_name    = "TeamWallets"
    group_hash_b  = keccak256(group_name.encode())

    # ERC20 transfer(to=team_wallet_1, amount)
    selector = bytes.fromhex("a9059cbb")
    data     = selector + team_wallet_1.rjust(32, b"\x00") + u256_be(amount)
    dlen     = len(data)

    digest = digest_for_user_action(to20=usdc, value_u256=0, data=data, data_len=dlen)
    sig, x, y, addr = sign_digest(priv, digest)

    user_action = {
        "to": usdc, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig], "signature_count": 1
    }
    rule = {
        "id": 1, "tx_type": TX_TYPE_TRANSFER,
        "destination": { "kind": DEST_PATTERN_GROUP, "name_hash_bytes": group_hash_b },
        "signer": { "kind": SIGNER_PATTERN_EXACT, "address": addr, "group_name_hash_bytes": b"\x00"*32, "threshold": 0 },
        "asset": { "kind": ASSET_PATTERN_EXACT, "address": usdc },
        "has_amount_max": False, "amount_max": 0,
        "has_function_selector": False, "function_selector": b"\x00"*4
    }
    ctx = {
        "groups": [team_wallet_1] + [b"\x00"*20]*(MAX_SIGNATURES-1),
        "group_name_hashes": [group_hash_b] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "allowlists": [b"\x00"*20]*MAX_SIGNATURES,
        "allowlist_name_hashes": [b"\x00"*32]*MAX_SIGNATURES,
        "signer_pubkeys_x": [x] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "signer_pubkeys_y": [y] + [b"\x00"*32]*(MAX_SIGNATURES-1),
    }
    return user_action, rule, ctx

# ---- Scenario 2: defi_swaps (ContractCall to ApprovedDEXs, asset ANY) ----
def defi_swaps(privkey_hex: str):
    priv = bytes.fromhex(privkey_hex.removeprefix("0x"))

    # Example approved DEX router (placeholder—replace with your real one if you like)
    dex_router = bytes.fromhex("7a250d5630b4cf539739df2c5dacb4c659f2488d")
    allowlist_name = "ApprovedDEXs"
    allowlist_hash_b = keccak256(allowlist_name.encode())

    # Minimal call: swapExactTokensForTokens selector 0x38ed1739 (no args for demo)
    selector = bytes.fromhex("38ed1739")
    data     = selector
    dlen     = len(data)

    digest = digest_for_user_action(to20=dex_router, value_u256=0, data=data, data_len=dlen)
    sig, x, y, addr = sign_digest(priv, digest)

    user_action = {
        "to": dex_router, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig], "signature_count": 1
    }
    rule = {
        "id": 2, "tx_type": TX_TYPE_CONTRACT_CALL,
        "destination": { "kind": DEST_PATTERN_ALLOWLIST, "name_hash_bytes": allowlist_hash_b },
        "signer": { "kind": SIGNER_PATTERN_EXACT, "address": addr, "group_name_hash_bytes": b"\x00"*32, "threshold": 0 },
        "asset": { "kind": ASSET_PATTERN_ANY, "address": b"\x00"*20 },
        "has_amount_max": False, "amount_max": 0,
        "has_function_selector": False, "function_selector": b"\x00"*4
    }
    ctx = {
        "groups": [b"\x00"*20]*MAX_SIGNATURES,
        "group_name_hashes": [b"\x00"*32]*MAX_SIGNATURES,
        "allowlists": [dex_router] + [b"\x00"*20]*(MAX_SIGNATURES-1),
        "allowlist_name_hashes": [allowlist_hash_b] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "signer_pubkeys_x": [x] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "signer_pubkeys_y": [y] + [b"\x00"*32]*(MAX_SIGNATURES-1),
    }
    return user_action, rule, ctx

# ---- Scenario 3: supply_lending (Transfer to ApprovedLendingProtocols, asset EXACT USDC) ----
def supply_lending(privkey_hex: str):
    priv = bytes.fromhex(privkey_hex.removeprefix("0x"))

    lending_pool = bytes.fromhex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")  # placeholder
    allowlist_name = "ApprovedLendingProtocols"
    allowlist_hash_b = keccak256(allowlist_name.encode())

    usdc   = bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    amount = 2_500 * 10**6

    selector = bytes.fromhex("a9059cbb")
    data     = selector + lending_pool.rjust(32, b"\x00") + u256_be(amount)
    dlen     = len(data)

    digest = digest_for_user_action(to20=usdc, value_u256=0, data=data, data_len=dlen)
    sig, x, y, addr = sign_digest(priv, digest)

    user_action = {
        "to": usdc, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig], "signature_count": 1
    }
    rule = {
        "id": 3, "tx_type": TX_TYPE_TRANSFER,
        "destination": { "kind": DEST_PATTERN_ALLOWLIST, "name_hash_bytes": allowlist_hash_b },
        "signer": { "kind": SIGNER_PATTERN_EXACT, "address": addr, "group_name_hash_bytes": b"\x00"*32, "threshold": 0 },
        "asset": { "kind": ASSET_PATTERN_EXACT, "address": usdc },
        "has_amount_max": False, "amount_max": 0,
        "has_function_selector": False, "function_selector": b"\x00"*4
    }
    ctx = {
        "groups": [b"\x00"*20]*MAX_SIGNATURES,
        "group_name_hashes": [b"\x00"*32]*MAX_SIGNATURES,
        "allowlists": [lending_pool] + [b"\x00"*20]*(MAX_SIGNATURES-1),
        "allowlist_name_hashes": [allowlist_hash_b] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "signer_pubkeys_x": [x] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "signer_pubkeys_y": [y] + [b"\x00"*32]*(MAX_SIGNATURES-1),
    }
    return user_action, rule, ctx

# ---- Scenario 4: interact_dapps (ContractCall to ApprovedLendingProtocols, asset ANY) ----
def interact_dapps(privkey_hex: str):
    priv = bytes.fromhex(privkey_hex.removeprefix("0x"))

    protocol = bytes.fromhex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")  # placeholder
    allowlist_name = "ApprovedLendingProtocols"
    allowlist_hash_b = keccak256(allowlist_name.encode())

    selector = bytes.fromhex("abcdef01")  # arbitrary function for demo
    data     = selector
    dlen     = len(data)

    digest = digest_for_user_action(to20=protocol, value_u256=0, data=data, data_len=dlen)
    sig, x, y, addr = sign_digest(priv, digest)

    user_action = {
        "to": protocol, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig], "signature_count": 1
    }
    rule = {
        "id": 4, "tx_type": TX_TYPE_CONTRACT_CALL,
        "destination": { "kind": DEST_PATTERN_ALLOWLIST, "name_hash_bytes": allowlist_hash_b },
        "signer": { "kind": SIGNER_PATTERN_EXACT, "address": addr, "group_name_hash_bytes": b"\x00"*32, "threshold": 0 },
        "asset": { "kind": ASSET_PATTERN_ANY, "address": b"\x00"*20 },
        "has_amount_max": False, "amount_max": 0,
        "has_function_selector": False, "function_selector": b"\x00"*4
    }
    ctx = {
        "groups": [b"\x00"*20]*MAX_SIGNATURES,
        "group_name_hashes": [b"\x00"*32]*MAX_SIGNATURES,
        "allowlists": [protocol] + [b"\x00"*20]*(MAX_SIGNATURES-1),
        "allowlist_name_hashes": [allowlist_hash_b] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "signer_pubkeys_x": [x] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "signer_pubkeys_y": [y] + [b"\x00"*32]*(MAX_SIGNATURES-1),
    }
    return user_action, rule, ctx

# ---- Scenario 5: amount_limits (Transfer to Group TeamWallets, EXACT USDC, max 10k) ----
def amount_limits(privkey_hex: str):
    priv = bytes.fromhex(privkey_hex.removeprefix("0x"))

    team_wallet_1 = bytes.fromhex("1111111111111111111111111111111111111111")
    usdc          = bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    amount        = 8_000 * 10**6  # within the 10,000 limit
    max_amount    = 10_000 * 10**6

    group_name    = "TeamWallets"
    group_hash_b  = keccak256(group_name.encode())

    selector = bytes.fromhex("a9059cbb")
    data     = selector + team_wallet_1.rjust(32, b"\x00") + u256_be(amount)
    dlen     = len(data)

    digest = digest_for_user_action(to20=usdc, value_u256=0, data=data, data_len=dlen)
    sig, x, y, addr = sign_digest(priv, digest)

    user_action = {
        "to": usdc, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig], "signature_count": 1
    }
    rule = {
        "id": 5, "tx_type": TX_TYPE_TRANSFER,
        "destination": { "kind": DEST_PATTERN_GROUP, "name_hash_bytes": group_hash_b },
        "signer": { "kind": SIGNER_PATTERN_EXACT, "address": addr, "group_name_hash_bytes": b"\x00"*32, "threshold": 0 },
        "asset": { "kind": ASSET_PATTERN_EXACT, "address": usdc },  # using EXACT USDC (no asset allowlist in circuit)
        "has_amount_max": True, "amount_max": max_amount,
        "has_function_selector": False, "function_selector": b"\x00"*4
    }
    ctx = {
        "groups": [team_wallet_1] + [b"\x00"*20]*(MAX_SIGNATURES-1),
        "group_name_hashes": [group_hash_b] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "allowlists": [b"\x00"*20]*MAX_SIGNATURES,
        "allowlist_name_hashes": [b"\x00"*32]*MAX_SIGNATURES,
        "signer_pubkeys_x": [x] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "signer_pubkeys_y": [y] + [b"\x00"*32]*(MAX_SIGNATURES-1),
    }
    return user_action, rule, ctx

# ---- Scenario 6: function_level_controls (ContractCall on DEX, specific selector) ----
def function_level_controls(privkey_hex: str):
    priv = bytes.fromhex(privkey_hex.removeprefix("0x"))

    dex_router = bytes.fromhex("7a250d5630b4cf539739df2c5dacb4c659f2488d")  # placeholder
    allowlist_name = "ApprovedDEXs"
    allowlist_hash_b = keccak256(allowlist_name.encode())

    # swapExactETHForTokens selector
    selector = bytes.fromhex("7ff36ab5")
    data     = selector
    dlen     = len(data)

    digest = digest_for_user_action(to20=dex_router, value_u256=0, data=data, data_len=dlen)
    sig, x, y, addr = sign_digest(priv, digest)

    user_action = {
        "to": dex_router, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig], "signature_count": 1
    }
    rule = {
        "id": 6, "tx_type": TX_TYPE_CONTRACT_CALL,
        "destination": { "kind": DEST_PATTERN_ALLOWLIST, "name_hash_bytes": allowlist_hash_b },
        "signer": { "kind": SIGNER_PATTERN_EXACT, "address": addr, "group_name_hash_bytes": b"\x00"*32, "threshold": 0 },
        "asset": { "kind": ASSET_PATTERN_ANY, "address": b"\x00"*20 },
        "has_amount_max": False, "amount_max": 0,
        "has_function_selector": True, "function_selector": selector
    }
    ctx = {
        "groups": [b"\x00"*20]*MAX_SIGNATURES,
        "group_name_hashes": [b"\x00"*32]*MAX_SIGNATURES,
        "allowlists": [dex_router] + [b"\x00"*20]*(MAX_SIGNATURES-1),
        "allowlist_name_hashes": [allowlist_hash_b] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "signer_pubkeys_x": [x] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "signer_pubkeys_y": [y] + [b"\x00"*32]*(MAX_SIGNATURES-1),
    }
    return user_action, rule, ctx

# ---- Scenario 7: advanced_signer_policies (Threshold 2 in GovernanceSigners) ----
def advanced_signer_policies(privkey_hex_1: str, privkey_hex_2: str):
    k1 = bytes.fromhex(privkey_hex_1.removeprefix("0x"))
    k2 = bytes.fromhex(privkey_hex_2.removeprefix("0x"))

    dex_router = bytes.fromhex("7a250d5630b4cf539739df2c5dacb4c659f2488d")  # placeholder
    group_name = "GovernanceSigners"
    group_hash_b = keccak256(group_name.encode())

    # Simple call (selector only)
    selector = bytes.fromhex("38ed1739")
    data     = selector
    dlen     = len(data)

    digest = digest_for_user_action(to20=dex_router, value_u256=0, data=data, data_len=dlen)

    sig1, x1, y1, addr1 = sign_digest(k1, digest)
    sig2, x2, y2, addr2 = sign_digest(k2, digest)

    user_action = {
        "to": dex_router, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig1, sig2], "signature_count": 2
    }
    rule = {
        "id": 7, "tx_type": TX_TYPE_CONTRACT_CALL,
        "destination": { "kind": DEST_PATTERN_ALLOWLIST, "name_hash_bytes": group_hash_b },  # <-- NOTE: destination should be DEX allowlist in text
        "signer": { "kind": SIGNER_PATTERN_THRESHOLD, "address": b"\x00"*20, "group_name_hash_bytes": group_hash_b, "threshold": 2 },
        "asset": { "kind": ASSET_PATTERN_ANY, "address": b"\x00"*20 },
        "has_amount_max": False, "amount_max": 0,
        "has_function_selector": False, "function_selector": b"\x00"*4
    }
    # Fix destination allowlist to DEXs, not GovernanceSigners name; keep GovernanceSigners for signer group
    dex_allowlist_name = "ApprovedDEXs"
    dex_allowlist_hash_b = keccak256(dex_allowlist_name.encode())

    rule["destination"]["name_hash_bytes"] = dex_allowlist_hash_b  # correct the dest allowlist

    # ctx: signer group membership (addresses), + dest allowlist member
    ctx_groups = [addr1, addr2] + [b"\x00"*20]*(MAX_SIGNATURES-2)
    ctx_group_hashes = [group_hash_b, group_hash_b] + [b"\x00"*32]*(MAX_SIGNATURES-2)

    ctx = {
        "groups": ctx_groups,
        "group_name_hashes": ctx_group_hashes,
        "allowlists": [dex_router] + [b"\x00"*20]*(MAX_SIGNATURES-1),
        "allowlist_name_hashes": [dex_allowlist_hash_b] + [b"\x00"*32]*(MAX_SIGNATURES-1),
        "signer_pubkeys_x": [x1, x2] + [b"\x00"*32]*(MAX_SIGNATURES-2),
        "signer_pubkeys_y": [y1, y2] + [b"\x00"*32]*(MAX_SIGNATURES-2),
    }
    return user_action, rule, ctx

# ---- CLI ----
SCENARIOS_ONE_KEY = {
    "contributor_payments": contributor_payments,
    "defi_swaps": defi_swaps,
    "supply_lending": supply_lending,
    "interact_dapps": interact_dapps,
    "amount_limits": amount_limits,
    "function_level_controls": function_level_controls,
}
SCENARIOS_TWO_KEYS = {
    "advanced_signer_policies": advanced_signer_policies,
}

def main():
    parser = argparse.ArgumentParser(description="Generate Prover.toml for zkpoex examples")
    parser.add_argument("--scenario", choices=list(SCENARIOS_ONE_KEY.keys()) + list(SCENARIOS_TWO_KEYS.keys()) + ["all"], default="contributor_payments")
    parser.add_argument("--key", help="hex private key for signer #1 (no 0x needed)", default="01"*32)
    parser.add_argument("--key2", help="hex private key for signer #2 (threshold scenarios)", default="02"*32)
    parser.add_argument("--out", help="output path (single scenario). For --scenario all, files are named Prover_<name>.toml")
    args = parser.parse_args()

    if args.scenario == "all":
        for name, fn in SCENARIOS_ONE_KEY.items():
            ua, r, c = fn(args.key)
            write_toml(ua, r, c, f"Prover_{name}.toml")
        for name, fn in SCENARIOS_TWO_KEYS.items():
            ua, r, c = fn(args.key, args.key2)
            write_toml(ua, r, c, f"Prover_{name}.toml")
    else:
        if args.scenario in SCENARIOS_ONE_KEY:
            ua, r, c = SCENARIOS_ONE_KEY[args.scenario](args.key)
        else:
            ua, r, c = SCENARIOS_TWO_KEYS[args.scenario](args.key, args.key2)

        print(f"Generating Prover.toml for scenario '{args.scenario}'")
        out_path = args.out or "Prover.toml"
        write_toml(ua, r, c, out_path)

if __name__ == "__main__":
    main()
