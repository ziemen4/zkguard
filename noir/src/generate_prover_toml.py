import toml
from eth_hash.auto import keccak
from coincurve import PrivateKey

MAX_CALLDATA_SIZE = 256
MAX_SIGNATURES = 5
SIGNATURE_SIZE = 65

# --- Helper Functions ---

def keccak256(data: bytes) -> bytes:
    """Computes the Keccak-256 hash of the input bytes."""
    return keccak(data)

def format_hex_array(
    data_bytes: bytes,
    *,
    pad_to: int | None = None,
    pad_byte: int = 0x00,
    pad_side: str = "right",  # "right" for calldata; use "left" if you ever need left-padding
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

def format_hex_string(data_bytes: bytes) -> str:
    """Formats bytes into a single TOML hex string (e.g., "0x...")."""
    return f"0x{data_bytes.hex()}"
    
BN254_SCALAR_MODULUS = int(
    "21888242871839275222246405745257275088548364400416034343698204186575808495617"
)

def bytes32_to_field_hex(b: bytes) -> str:
    """
    Interpret b as a big-endian integer, reduce mod BN254 scalar field,
    and return canonical 0x-prefixed 32-byte hex.
    """
    v = int.from_bytes(b, "big") % BN254_SCALAR_MODULUS
    return f"0x{v:064x}"

def eth_addr_from_xy(x: bytes, y: bytes) -> bytes:
    return keccak(x + y)[12:]  # last 20 bytes

def digest_for_user_action(to20: bytes, value_u256: int, data: bytes, data_len: int) -> bytes:
    buf = bytearray()
    buf += to20
    buf += value_u256.to_bytes(32, 'big')
    buf += data[:data_len]
    return keccak(bytes(buf))

def sign_digest(privkey_bytes: bytes, digest32: bytes) -> tuple[bytes, bytes, bytes, bytes]:
    pk = PrivateKey(privkey_bytes)
    sig65 = pk.sign_recoverable(digest32, hasher=None)            # 65 bytes
    pub_uncompressed = pk.public_key.format(compressed=False)     # 0x04 || X || Y
    x, y = pub_uncompressed[1:33], pub_uncompressed[33:65]

    addr = eth_addr_from_xy(x, y)
    return sig65, x, y, addr

# --- Scenario Definition: Contributor Payments ---

def define_contributor_payments_scenario(signer_privkey_hex: str):
    """Defines all data for the contributor payments example."""
    
    # Addresses and Values
    privkey_bytes = bytes.fromhex(signer_privkey_hex.removeprefix("0x"))
    dao_safe_address = bytes.fromhex("dddddddddddddddddddddddddddddddddddddddd")
    team_wallet_1 = bytes.fromhex("1111111111111111111111111111111111111111")
    usdc_contract = bytes.fromhex("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")
    payment_amount = 5000 * (10**6) # 5,000 USDC with 6 decimals

    # Group Definitions
    team_wallets_group_name = "TeamWallets"
    team_wallets_group = {
        "name": team_wallets_group_name,
        "members": [team_wallet_1],
        "name_hash": keccak256(team_wallets_group_name.encode('utf-8'))
    }
    
    # --- User Action ---
    # `transfer(address to, uint256 amount)`
    transfer_selector = bytes.fromhex("a9059cbb")
    calldata = (
        transfer_selector +
        team_wallet_1.rjust(32, b'\x00') +
        payment_amount.to_bytes(32, 'big')
    )
    data_len = len(calldata)

    digest = digest_for_user_action(
        to20=usdc_contract,
        value_u256=0,
        data=calldata,
        data_len=data_len,
    )
    # Sign & derive EOA address
    sig65, x, y, signer_addr = sign_digest(privkey_bytes, digest)
    
    user_action = {
        "to": usdc_contract,
        "value": 0,
        "data": calldata,
        "data_len": len(calldata),
        "signatures": [sig65],
        "signature_count": 1
    }
    
    # --- Policy Rule ---
    policy_rule = {
        "id": 1,
        "tx_type": 0, # Transfer
        "destination": {
            "kind": 1, # Group
            "name_hash": team_wallets_group["name_hash"]
        },
        "signer": {
            "kind": 1, # Exact
            "address": signer_addr,
            "group_name_hash": b'\x00' * 32, # Unused in Exact mode
            "threshold": 0
        },
        "asset": {
            "kind": 1, # Exact
            "address": usdc_contract
        },
        "has_amount_max": False,
        "amount_max": 0,
        "has_function_selector": False,
        "function_selector": b'\x00' * 4
    }

    # --- Verification Context (ctx) ---
    # Noir requires fixed-size arrays, so we pad them.
    MAX_SIGNATURES = 5 
    
    ctx_groups = [b'\x00' * 20] * MAX_SIGNATURES
    ctx_group_hashes = [b'\x00' * 32] * MAX_SIGNATURES
    
    # Populate the first slot with our TeamWallets group info
    ctx_groups[0] = team_wallets_group["members"][0]
    ctx_group_hashes[0] = team_wallets_group["name_hash"]
    
    # Placeholder for public key. In a real scenario, this must match the signer and signature.
    signer_pubkey_x = [x] + [b"\x00"*32]*(MAX_SIGNATURES-1)
    signer_pubkey_y = [y] + [b"\x00"*32]*(MAX_SIGNATURES-1)
    
    ctx = {
        "groups": ctx_groups,
        "group_name_hashes": ctx_group_hashes,
        "allowlists": [b'\x00' * 20] * MAX_SIGNATURES,
        "allowlist_name_hashes": [b'\x00' * 32] * MAX_SIGNATURES,
        "signer_pubkeys_x": signer_pubkey_x,
        "signer_pubkeys_y": signer_pubkey_y
    }
    
    return user_action, policy_rule, ctx

def generate_toml_file(signer_privkey_hex: str, out_path: str = "Prover.toml"):
    """Generates the Prover.toml file from the scenario definition."""
    user_action, rule, ctx = define_contributor_payments_scenario(signer_privkey_hex)
    
    # Build the final dictionary with TOML-compatible formatting
    signatures = pad_list(user_action["signatures"], MAX_SIGNATURES, b"\x00" * SIGNATURE_SIZE)
    ctx_groups = pad_list(ctx["groups"], MAX_SIGNATURES, b"\x00" * 20)
    ctx_allow = pad_list(ctx["allowlists"], MAX_SIGNATURES, b"\x00" * 20)
    pkx = pad_list(ctx["signer_pubkeys_x"], MAX_SIGNATURES, b"\x00" * 32)
    pky = pad_list(ctx["signer_pubkeys_y"], MAX_SIGNATURES, b"\x00" * 32)
    toml_data = {
        "user_action": {
            "to": format_hex_array(user_action["to"], pad_to=20),
            "value": str(user_action["value"]),
            "data": format_hex_array(user_action["data"], pad_to=MAX_CALLDATA_SIZE, pad_side="right"),
            "data_len": str(user_action["data_len"]),
            "signatures": [format_hex_array(s, pad_to=SIGNATURE_SIZE) for s in signatures],
            "signature_count": str(user_action["signature_count"])
        },
        "rule": {
            "id": str(rule["id"]),
            "tx_type": str(rule["tx_type"]),
            "destination": {
                "kind": str(rule["destination"]["kind"]),
                "name_hash": bytes32_to_field_hex(rule["destination"]["name_hash"])
            },
            "signer": {
                "kind": str(rule["signer"]["kind"]),
                "address": format_hex_array(rule["signer"]["address"], pad_to=20),
                "group_name_hash": bytes32_to_field_hex(rule["signer"]["group_name_hash"]),
                "threshold": str(rule["signer"]["threshold"])
            },
            "asset": {
                "kind": str(rule["asset"]["kind"]),
                "address": format_hex_array(rule["asset"]["address"], pad_to=20)
            },
            "has_amount_max": rule["has_amount_max"],
            "amount_max": str(rule["amount_max"]),
            "has_function_selector": rule["has_function_selector"],
            "function_selector": format_hex_array(rule["function_selector"], pad_to=4)
        },
        "ctx": {
            "groups": [format_hex_array(g, pad_to=20) for g in ctx_groups],
            "group_name_hashes": [bytes32_to_field_hex(h) for h in pad_list(ctx["group_name_hashes"], MAX_SIGNATURES, b'\x00' * 32)],
            "allowlists": [format_hex_array(a, pad_to=20) for a in ctx_allow],
            "allowlist_name_hashes": [bytes32_to_field_hex(h) for h in ctx["allowlist_name_hashes"]],
            "signer_pubkeys_x": [format_hex_array(pk, pad_to=32) for pk in pkx],
            "signer_pubkeys_y": [format_hex_array(pk, pad_to=32) for pk in pky]
        }
    }
    
    with open(out_path, "w") as f:
        toml.dump(toml_data, f)
        
    print(f"✅ Successfully generated {out_path} for 'contributor_payments' scenario.")

if __name__ == "__main__":
    # Example deterministic key for testing (DO NOT USE IN PROD)
    generate_toml_file(signer_privkey_hex="01"*32)