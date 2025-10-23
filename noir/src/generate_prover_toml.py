# generate_prover_toml.py
import argparse
import os
import toml
import hashlib
from eth_hash.auto import keccak
from coincurve import PrivateKey

# ---- Must match your Noir constants ----
MAX_CALLDATA_SIZE = 256
MAX_SIGNATURES = 5
SIGNATURE_SIZE = 65
MAX_MERKLE_DEPTH = 64  # Must match Noir constant

TX_TYPE_TRANSFER = 0
TX_TYPE_CONTRACT_CALL = 1

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

# secp256k1 order (for low-s normalization)
SECP256K1_N = int(
    "0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141", 16
)

# Two deterministic dummy keys: A (for placeholder signature) and B (for placeholder pubkey)
DUMMY_PRIV_A = bytes.fromhex("11" * 32)
DUMMY_PRIV_B = bytes.fromhex("22" * 32)

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

def pad_list(lst, length, filler: bytes):
    return lst[:length] + [filler] * max(0, length - len(lst))

def u256_be(n: int) -> bytes:
    return n.to_bytes(32, "big")

def eth_addr_from_xy(x: bytes, y: bytes) -> bytes:
    # (Your original: keccak(x||y)[12:])
    return keccak(x + y)[12:]

def digest_for_user_action(to20: bytes, value_u256: int, data: bytes, data_len: int) -> bytes:
    buf = bytearray()
    buf += to20
    buf += u256_be(value_u256)
    buf += data[:data_len]
    return keccak(bytes(buf))

def _low_s_normalize(sig65: bytes) -> bytes:
    # sig65 = r(32) || s(32) || v(1)
    if len(sig65) != 65:
        raise ValueError("expected 65-byte signature {r,s,v}")
    r = int.from_bytes(sig65[0:32], "big")
    s = int.from_bytes(sig65[32:64], "big")
    v = sig65[64]

    # Normalize to low-s
    if s > SECP256K1_N // 2:
        s = SECP256K1_N - s
        # Flip parity bit of v (supports 27/28 or 0/1)
        if v in (27, 28):
            v = 55 - v          # 27<->28
        else:
            v = v ^ 1           # 0<->1

    r_b = r.to_bytes(32, "big")
    s_b = s.to_bytes(32, "big")
    return r_b + s_b + bytes([v])

def sign_digest(privkey_bytes: bytes, digest32: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    pk = PrivateKey(privkey_bytes)
    sig65 = pk.sign_recoverable(digest32, hasher=None)
    sig65 = _low_s_normalize(sig65)

    pub_uncompressed = pk.public_key.format(compressed=False)  # 0x04||X||Y
    x, y = pub_uncompressed[1:33], pub_uncompressed[33:65]
    addr = eth_addr_from_xy(x, y)
    return sig65, x, y, addr

def make_placeholder_for_digest(digest32: bytes) -> tuple[bytes, bytes, bytes]:
    """
    Produce a valid-but-non-matching placeholder:
      - signature over 'digest32' using DummyKey A
      - public key (x,y) from DummyKey B
    This ensures verify_signature(pkB, sigA, digest32) returns false *cleanly*.
    """
    sig65_A, _, _, _ = sign_digest(DUMMY_PRIV_A, digest32)
    _, xB, yB, _ = sign_digest(DUMMY_PRIV_B, b"\x01" * 32)  # any digest; we only need pk from B
    return sig65_A, xB, yB

def replace_zeros_with_placeholder(items: list[bytes], placeholder: bytes) -> list[bytes]:
    """
    Replace any all-zero item with 'placeholder'; keep non-zero entries intact.
    """
    out = []
    zero = bytes(len(placeholder))
    for it in items:
        if len(it) == len(placeholder) and it == zero:
            out.append(placeholder)
        else:
            out.append(it)
    return out

def to_bytearrays(lst: list[bytes], size: int) -> list[bytes]:
    """Ensure each element is exactly 'size' bytes (truncate or right-pad with zeros)."""
    out = []
    for b in lst:
        if len(b) > size:
            out.append(b[:size])
        elif len(b) < size:
            out.append(b + b"\x00" * (size - len(b)))
        else:
            out.append(b)
    return out

# --- Merkle helpers (No changes to existing behavior; only added outputs) ---
def _field_bytes32_from_bytes32(b: bytes) -> bytes:
    """
    Interpret `b` as big-endian integer, reduce mod BN254, return 32-byte big-endian.
    Mirrors Field::from_be_bytes and Field::to_be_bytes inside Noir for consistency.
    """
    v = int.from_bytes(b, "big") % BN254_SCALAR_MODULUS
    return v.to_bytes(32, "big")

def _u256_to_be32(n: int) -> bytes:
    return int(n).to_bytes(32, "big")

def serialize_rule_to_leaf_preimage(rule: dict) -> bytes:
    """
    Build the fixed 271-byte preimage according to the Noir circuit layout:
      tx_type(32) | dest.kind(32) | dest.name_hash(32)
      | signer.kind(32) | signer.address(20) | signer.group_name_hash(32) | signer.threshold(1)
      | asset.kind(32) | asset.address(20)
      | has_amount_max(1) | amount_max(32)
      | has_function_selector(1) | function_selector(4)
    All numeric Fields are 32-byte big-endian. Booleans are 1 byte (0/1).
    """
    out = bytearray()

    # tx_type
    out += _u256_to_be32(rule["tx_type"])  # Field -> 32

    # destination
    dest = rule["destination"]
    out += _u256_to_be32(dest["kind"])  # Field -> 32
    out += _field_bytes32_from_bytes32(dest["name_hash_bytes"])  # Field -> 32

    # signer
    signer = rule["signer"]
    out += _u256_to_be32(signer["kind"])              # Field -> 32
    out += signer["address"]                           # [u8;20]
    out += _field_bytes32_from_bytes32(signer["group_name_hash_bytes"])  # Field -> 32
    out += bytes([int(signer["threshold"]) & 0xff])   # u8

    # asset
    asset = rule["asset"]
    out += _u256_to_be32(asset["kind"])               # Field -> 32
    out += asset["address"]                            # [u8;20]

    # amount / selector flags and values
    out += bytes([1 if rule["has_amount_max"] else 0])
    out += _u256_to_be32(rule["amount_max"])          # Field -> 32
    out += bytes([1 if rule["has_function_selector"] else 0])
    fs = rule["function_selector"] or b"\x00" * 4
    out += fs[:4].ljust(4, b"\x00")                   # [u8;4]

    # Sanity: ensure 271 bytes
    assert len(out) == 271, f"leaf preimage must be 271 bytes, got {len(out)}"
    return bytes(out)

def compute_merkle_singleton(rule: dict) -> tuple[bytes, list[bytes], int, int]:
    """
    Compute a singleton Merkle tree (one-leaf) for the given rule.
    Returns: (root32, siblings, depth, leaf_index)
    depth = 0, leaf_index = 0, siblings = [zero32]*MAX_MERKLE_DEPTH
    """
    preimage = serialize_rule_to_leaf_preimage(rule)
    leaf = hashlib.sha256(preimage).digest()
    root = leaf
    zero32 = bytes(32)
    siblings = [zero32 for _ in range(MAX_MERKLE_DEPTH)]
    return root, siblings, 0, 0

def write_toml(user_action, rule, ctx, out_path: str):
    # digest was computed in the scenario and stored (not written to TOML)
    digest = user_action["_digest"]

    # Build placeholder (valid-but-non-matching) for inactive slots
    ph_sig65, ph_x, ph_y = make_placeholder_for_digest(digest)

    # --- User action fields
    data_padded = user_action["data"].ljust(MAX_CALLDATA_SIZE, b"\x00")

    # Signatures: real + placeholders to fill up MAX_SIGNATURES
    real_sigs = user_action["signatures"]  # list[bytes], each 65 bytes
    placeholder_block = [ph_sig65] * (MAX_SIGNATURES - len(real_sigs))
    sigs_full = (real_sigs + placeholder_block)[:MAX_SIGNATURES]
    sigs_full = to_bytearrays(sigs_full, SIGNATURE_SIZE)

    # --- Context pubkeys: replace zero entries with placeholder pkB, then pad
    pkx = ctx["signer_pubkeys_x"][:]
    pky = ctx["signer_pubkeys_y"][:]

    # Normalize sizes to 32 bytes and replace zeroes with placeholder
    pkx = to_bytearrays(pkx, 32)
    pky = to_bytearrays(pky, 32)
    pkx = replace_zeros_with_placeholder(pkx, ph_x)
    pky = replace_zeros_with_placeholder(pky, ph_y)
    # pad to MAX_SIGNATURES
    if len(pkx) < MAX_SIGNATURES:
        pkx += [ph_x] * (MAX_SIGNATURES - len(pkx))
    if len(pky) < MAX_SIGNATURES:
        pky += [ph_y] * (MAX_SIGNATURES - len(pky))
    pkx = pkx[:MAX_SIGNATURES]
    pky = pky[:MAX_SIGNATURES]

    # Compute Merkle root + path for the provided rule (singleton tree)
    root, siblings, depth, leaf_index = compute_merkle_singleton(rule)

    toml_data = {
        "user_action": {
            "to": format_hex_array(user_action["to"], pad_to=20),
            "value": user_action["value"],
            "data": format_hex_array(data_padded, pad_to=MAX_CALLDATA_SIZE),
            "data_len": user_action["data_len"],
            "signatures": [format_hex_array(s, pad_to=SIGNATURE_SIZE) for s in sigs_full],
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
            "signer_pubkeys_x": [format_hex_array(pk, pad_to=32) for pk in pkx],
            "signer_pubkeys_y": [format_hex_array(pk, pad_to=32) for pk in pky],
        },
        # New: policy Merkle inputs expected by Noir main
        "policy_merkle_root": format_hex_array(root, pad_to=32),
        "policy_merkle_path": {
            "leaf_index": leaf_index,
            "depth": depth,
            "siblings": [format_hex_array(s, pad_to=32) for s in siblings],
        },
    }

    # Don't write the digest to TOML
    with open(out_path, "w") as f:
        toml.dump(toml_data, f)
    print(f"✅ Wrote {out_path}")

# ---- Scenarios ----
def contributor_payments(privkey_hex: str):
    priv = bytes.fromhex(privkey_hex.removeprefix("0x"))

    team_wallet_1 = bytes.fromhex("1111111111111111111111111111111111111111")
    usdc          = bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    amount        = 5_000 * 10**6

    group_name    = "TeamWallets"
    group_hash_b  = keccak256(group_name.encode())

    selector = bytes.fromhex("a9059cbb")
    data     = selector + team_wallet_1.rjust(32, b"\x00") + u256_be(amount)
    dlen     = len(data)

    digest = digest_for_user_action(to20=usdc, value_u256=0, data=data, data_len=dlen)
    sig, x, y, addr = sign_digest(priv, digest)

    user_action = {
        "to": usdc, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig], "signature_count": 1,
        "_digest": digest,
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

def defi_swaps(privkey_hex: str):
    priv = bytes.fromhex(privkey_hex.removeprefix("0x"))

    dex_router = bytes.fromhex("7a250d5630b4cf539739df2c5dacb4c659f2488d")
    allowlist_name = "ApprovedDEXs"
    allowlist_hash_b = keccak256(allowlist_name.encode())

    selector = bytes.fromhex("38ed1739")
    data     = selector
    dlen     = len(data)

    digest = digest_for_user_action(to20=dex_router, value_u256=0, data=data, data_len=dlen)
    sig, x, y, addr = sign_digest(priv, digest)

    user_action = {
        "to": dex_router, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig], "signature_count": 1,
        "_digest": digest,
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
        "signatures": [sig], "signature_count": 1,
        "_digest": digest,
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

def interact_dapps(privkey_hex: str):
    priv = bytes.fromhex(privkey_hex.removeprefix("0x"))

    protocol = bytes.fromhex("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")  # placeholder
    allowlist_name = "ApprovedLendingProtocols"
    allowlist_hash_b = keccak256(allowlist_name.encode())

    selector = bytes.fromhex("abcdef01")  # arbitrary
    data     = selector
    dlen     = len(data)

    digest = digest_for_user_action(to20=protocol, value_u256=0, data=data, data_len=dlen)
    sig, x, y, addr = sign_digest(priv, digest)

    user_action = {
        "to": protocol, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig], "signature_count": 1,
        "_digest": digest,
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

def amount_limits(privkey_hex: str):
    priv = bytes.fromhex(privkey_hex.removeprefix("0x"))

    team_wallet_1 = bytes.fromhex("1111111111111111111111111111111111111111")
    usdc          = bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    amount        = 8_000 * 10**6
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
        "signatures": [sig], "signature_count": 1,
        "_digest": digest,
    }
    rule = {
        "id": 5, "tx_type": TX_TYPE_TRANSFER,
        "destination": { "kind": DEST_PATTERN_GROUP, "name_hash_bytes": group_hash_b },
        "signer": { "kind": SIGNER_PATTERN_EXACT, "address": addr, "group_name_hash_bytes": b"\x00"*32, "threshold": 0 },
        "asset": { "kind": ASSET_PATTERN_EXACT, "address": usdc },
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

def function_level_controls(privkey_hex: str):
    priv = bytes.fromhex(privkey_hex.removeprefix("0x"))

    dex_router = bytes.fromhex("7a250d5630b4cf539739df2c5dacb4c659f2488d")
    allowlist_name = "ApprovedDEXs"
    allowlist_hash_b = keccak256(allowlist_name.encode())

    selector = bytes.fromhex("7ff36ab5")
    data     = selector
    dlen     = len(data)

    digest = digest_for_user_action(to20=dex_router, value_u256=0, data=data, data_len=dlen)
    sig, x, y, addr = sign_digest(priv, digest)

    user_action = {
        "to": dex_router, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig], "signature_count": 1,
        "_digest": digest,
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

def advanced_signer_policies(privkey_hex_1: str, privkey_hex_2: str):
    k1 = bytes.fromhex(privkey_hex_1.removeprefix("0x"))
    k2 = bytes.fromhex(privkey_hex_2.removeprefix("0x"))

    dex_router = bytes.fromhex("7a250d5630b4cf539739df2c5dacb4c659f2488d")
    group_name = "GovernanceSigners"
    group_hash_b = keccak256(group_name.encode())

    selector = bytes.fromhex("38ed1739")
    data     = selector
    dlen     = len(data)

    digest = digest_for_user_action(to20=dex_router, value_u256=0, data=data, data_len=dlen)

    sig1, x1, y1, addr1 = sign_digest(k1, digest)
    sig2, x2, y2, addr2 = sign_digest(k2, digest)

    user_action = {
        "to": dex_router, "value": 0, "data": data, "data_len": dlen,
        "signatures": [sig1, sig2], "signature_count": 2,
        "_digest": digest,
    }
    rule = {
        "id": 7, "tx_type": TX_TYPE_CONTRACT_CALL,
        # corrected to DEX allowlist
        "destination": { "kind": DEST_PATTERN_ALLOWLIST, "name_hash_bytes": keccak256(b"ApprovedDEXs") },
        "signer": { "kind": SIGNER_PATTERN_THRESHOLD, "address": b"\x00"*20, "group_name_hash_bytes": group_hash_b, "threshold": 2 },
        "asset": { "kind": ASSET_PATTERN_ANY, "address": b"\x00"*20 },
        "has_amount_max": False, "amount_max": 0,
        "has_function_selector": False, "function_selector": b"\x00"*4
    }

    ctx_groups = [addr1, addr2] + [b"\x00"*20]*(MAX_SIGNATURES-2)
    ctx_group_hashes = [group_hash_b, group_hash_b] + [b"\x00"*32]*(MAX_SIGNATURES-2)

    ctx = {
        "groups": ctx_groups,
        "group_name_hashes": ctx_group_hashes,
        "allowlists": [dex_router] + [b"\x00"*20]*(MAX_SIGNATURES-1),
        "allowlist_name_hashes": [keccak256(b"ApprovedDEXs")] + [b"\x00"*32]*(MAX_SIGNATURES-1),
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
