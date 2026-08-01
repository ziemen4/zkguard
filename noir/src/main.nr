mod policy;

use policy::{
    ASSET_PATTERN_ANY, ASSET_PATTERN_EXACT, AssetPattern, DEST_PATTERN_ALLOWLIST, DEST_PATTERN_ANY,
    DEST_PATTERN_EXACT, DEST_PATTERN_GROUP, DestinationPattern, MAX_CALLDATA_SIZE, MAX_SIGNATURES,
    PolicyLine, SIGNATURE_SIZE, SIGNER_PATTERN_ANY, SIGNER_PATTERN_EXACT, SIGNER_PATTERN_GROUP,
    SIGNER_PATTERN_THRESHOLD, SignerPattern, TX_TYPE_CONTRACT_CALL, TX_TYPE_TRANSFER, UserAction,
};

// --- Imports for Noir v1.0.0-beta.9 ---
use dep::keccak256::keccak256;
use dep::poseidon::poseidon2::Poseidon2;
use std::ecdsa_secp256k1::verify_signature;
// --------------------------------------

// A struct to hold all the public outputs for the verifier.
pub struct PublicOutputs {
    call_hash: [u8; 32],
    policy_hash: Field,
    groups_hash: [u8; 32],
    allow_hash: [u8; 32],
}

// ERC-20 `transfer(address,uint256)` selector.
global TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
// Pseudo-address for native ETH.
global ETH_ASSET: [u8; 20] = [0; 20];

fn bool_to_field(b: bool) -> Field {
    if b {
        1
    } else {
        0
    }
}

fn address_to_field(address: [u8; 20]) -> Field {
    let mut out: Field = 0;
    for i in 0..20 {
        out = (out * 256) + (address[i] as Field);
    }
    out
}

fn selector_to_field(selector: [u8; 4]) -> Field {
    let mut out: Field = 0;
    for i in 0..4 {
        out = (out * 256) + (selector[i] as Field);
    }
    out
}

fn hash_policy_leaf(rule: PolicyLine) -> Field {
    let destination_uses_name = (rule.destination.kind == DEST_PATTERN_GROUP)
        | (rule.destination.kind == DEST_PATTERN_ALLOWLIST);
    let destination_name = if destination_uses_name { rule.destination.name_hash } else { 0 };
    let destination_address = if rule.destination.kind == DEST_PATTERN_EXACT {
        rule.destination.address
    } else {
        ETH_ASSET
    };
    let signer_address = if rule.signer.kind == SIGNER_PATTERN_EXACT {
        rule.signer.address
    } else {
        ETH_ASSET
    };
    let signer_uses_group = (rule.signer.kind == SIGNER_PATTERN_GROUP)
        | (rule.signer.kind == SIGNER_PATTERN_THRESHOLD);
    let signer_group = if signer_uses_group { rule.signer.group_name_hash } else { 0 };
    let signer_threshold = if rule.signer.kind == SIGNER_PATTERN_THRESHOLD {
        rule.signer.threshold
    } else {
        0
    };
    let asset_address = if rule.asset.kind == ASSET_PATTERN_EXACT {
        rule.asset.address
    } else {
        ETH_ASSET
    };
    let amount_max = if rule.has_amount_max { rule.amount_max } else { 0 };
    let function_selector = if rule.has_function_selector {
        rule.function_selector
    } else {
        [0; 4]
    };

    Poseidon2::hash(
        [
            rule.tx_type,
            rule.destination.kind,
            destination_name,
            address_to_field(destination_address),
            rule.signer.kind,
            address_to_field(signer_address),
            signer_group,
            signer_threshold as Field,
            rule.asset.kind,
            address_to_field(asset_address),
            bool_to_field(rule.has_amount_max),
            amount_max,
            bool_to_field(rule.has_function_selector),
            selector_to_field(function_selector),
        ],
        14,
    )
}

// Minimal verification context (plus pubkeys for each signature slot).
pub struct VerificationContext {
    groups: [[u8; 20]; MAX_SIGNATURES],
    group_name_hashes: [Field; MAX_SIGNATURES],
    allowlists: [[u8; 20]; MAX_SIGNATURES],
    allowlist_name_hashes: [Field; MAX_SIGNATURES],

    // Pubkey per signature position; uncompressed (x,y) coordinates.
    signer_pubkeys_x: [[u8; 32]; MAX_SIGNATURES],
    signer_pubkeys_y: [[u8; 32]; MAX_SIGNATURES],
}

// Slices 4 bytes from a 256-byte calldata array.
fn slice_4_from_256(arr: [u8; 256], start: u32) -> [u8; 4] {
    let mut out = [0; 4];
    for i in 0..4 {
        out[i] = arr[start + i];
    }
    out
}

fn erc20_amount_bytes(data: [u8; 256]) -> [u8; 32] {
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = data[36 + i];
    }
    out
}

// Convert an Ethereum 65-byte sig (r||s||v) into 64 bytes (r||s) for std verifier.
fn sig64_from_eth(sig: [u8; SIGNATURE_SIZE]) -> [u8; 64] {
    let mut out = [0; 64];
    for i in 0..64 {
        out[i] = sig[i];
    }
    out
}

// keccak256(x||y): take last 20 bytes as ETH address.
fn eth_addr_from_pubkey(pubx: [u8; 32], puby: [u8; 32]) -> [u8; 20] {
    let mut pk = [0u8; 64];
    for i in 0..32 {
        pk[i] = pubx[i];
    }
    for i in 0..32 {
        pk[32 + i] = puby[i];
    }
    // keccak256 takes (bytes, len) in the external crate.
    let h: [u8; 32] = keccak256(pk, 64);
    let mut addr = [0u8; 20];
    for i in 0..20 {
        addr[i] = h[12 + i];
    }
    addr
}

// Hash a UserAction for signing: from(20) || to(20) || value(32 BE) || data[0..data_len].
fn hash_user_action(action: UserAction) -> [u8; 32] {
    let mut buf = [0u8; 20 + 20 + 32 + MAX_CALLDATA_SIZE];

    // from (20)
    for i in 0..20 {
        buf[i] = action.from[i];
    }

    // to (20)
    for i in 0..20 {
        buf[20 + i] = action.to[i];
    }

    // value --> 32-byte big-endian
    let val_be: [u8; 32] = action.value.to_be_bytes::<32>();
    for i in 0..32 {
        buf[40 + i] = val_be[i];
    }

    // data prefix up to action.data_len
    for i in 0..MAX_CALLDATA_SIZE {
        if i < action.data_len {
            buf[72 + i] = action.data[i];
        }
    }

    // External keccak256 requires (array, logical_length).
    let out: [u8; 32] = keccak256(buf, 72 + action.data_len);
    out
}

// Membership check for groups/allowlists under a given name-hash.
fn is_member(
    address: [u8; 20],
    members: [[u8; 20]; MAX_SIGNATURES],
    name_hashes: [Field; MAX_SIGNATURES],
    required_hash: Field,
) -> bool {
    let mut found = false;
    for i in 0..MAX_SIGNATURES {
        found = found | ((name_hashes[i] == required_hash) & (members[i] == address));
    }
    found
}

// Destination matches policy?
fn match_destination(
    pattern: DestinationPattern,
    addr: [u8; 20],
    ctx: VerificationContext,
) -> bool {
    let any = pattern.kind == DEST_PATTERN_ANY;
    let exact = (pattern.kind == DEST_PATTERN_EXACT) & (pattern.address == addr);
    let group = (pattern.kind == DEST_PATTERN_GROUP)
        & is_member(addr, ctx.groups, ctx.group_name_hashes, pattern.name_hash);
    let allowlist = (pattern.kind == DEST_PATTERN_ALLOWLIST)
        & is_member(
            addr,
            ctx.allowlists,
            ctx.allowlist_name_hashes,
            pattern.name_hash,
        );
    any | exact | group | allowlist
}

// Signer(s) match policy? (verify sigs, derive ETH address from pubkey, then match)
fn match_signer(
    pattern: SignerPattern,
    action: UserAction,
    ctx: VerificationContext,
    digest: [u8; 32],
) -> bool {
    let mut verified = [false; MAX_SIGNATURES];
    let mut signer_addresses = [[0u8; 20]; MAX_SIGNATURES];
    for i in 0..MAX_SIGNATURES {
        let sig = sig64_from_eth(action.signatures[i]);
        let px = ctx.signer_pubkeys_x[i];
        let py = ctx.signer_pubkeys_y[i];
        verified[i] = verify_signature(px, py, sig, digest);
        signer_addresses[i] = eth_addr_from_pubkey(px, py);
    }

    let exactly_one = action.signature_count == 1;
    let mut signer_members = [false; MAX_SIGNATURES];
    for i in 0..MAX_SIGNATURES {
        signer_members[i] = is_member(
            signer_addresses[i],
            ctx.groups,
            ctx.group_name_hashes,
            pattern.group_name_hash,
        );
    }

    let mut any_verified = false;
    let mut valid: u32 = 0;
    for i in 0..MAX_SIGNATURES {
        let active = i < action.signature_count;
        any_verified = any_verified | (active & verified[i]);

        let mut is_new_signer = true;
        for j in 0..MAX_SIGNATURES {
            let earlier = j < i;
            let prior_active = j < action.signature_count;
            let duplicate = earlier
                & prior_active
                & verified[j]
                & (signer_addresses[j] == signer_addresses[i]);
            is_new_signer = is_new_signer & !duplicate;
        }

        let value_contribution = active & verified[i] & signer_members[i] & is_new_signer;
        valid += if value_contribution { 1 } else { 0 };
    }

    let any = (pattern.kind == SIGNER_PATTERN_ANY) & any_verified;
    let exact = (pattern.kind == SIGNER_PATTERN_EXACT)
        & exactly_one
        & verified[0]
        & (signer_addresses[0] == pattern.address);
    let group = (pattern.kind == SIGNER_PATTERN_GROUP)
        & exactly_one
        & verified[0]
        & signer_members[0];
    let threshold = (pattern.kind == SIGNER_PATTERN_THRESHOLD) & (valid >= (pattern.threshold as u32));

    any | exact | group | threshold
}

// Asset pattern match.
fn match_asset(pattern: AssetPattern, asset: [u8; 20]) -> bool {
    (pattern.kind == ASSET_PATTERN_ANY)
        | ((pattern.kind == ASSET_PATTERN_EXACT) & (pattern.address == asset))
}

// Classify action --> (type, destination, asset, amount(Field))
fn classify_user_action(action: UserAction) -> (Field, [u8; 20], [u8; 20], Field) {
    let selector = slice_4_from_256(action.data, 0);
    let is_erc20_transfer = (action.data_len >= 4) & (selector == TRANSFER_SELECTOR);

    let mut out_ty = TX_TYPE_CONTRACT_CALL;
    let mut dest: [u8; 20] = action.to;
    let mut asset: [u8; 20] = ETH_ASSET;
    let mut amount: Field = 0;

    if action.value != 0 {
        // Native ETH transfer
        out_ty = TX_TYPE_TRANSFER;
        dest = action.to;
        asset = ETH_ASSET;
        amount = action.value;
    } else if is_erc20_transfer {
        // ERC20 transfer(address,uint256)
        out_ty = TX_TYPE_TRANSFER;

        // recipient is bytes 16..36 of first arg
        let mut rcpt = [0u8; 20];
        for i in 0..20 {
            rcpt[i] = action.data[16 + i];
        }
        dest = rcpt;

        // asset is the token contract
        asset = action.to;

        // amount is second arg (32 bytes big-endian) --> Field
        let amount_be = erc20_amount_bytes(action.data);
        amount = Field::from_be_bytes::<32>(amount_be);
    } else {
        // Generic call
        out_ty = TX_TYPE_CONTRACT_CALL;
        dest = action.to;
        asset = ETH_ASSET;
        amount = 0;
    }

    (out_ty, dest, asset, amount)
}

// Hashes a list of members and their corresponding name hashes.
fn hash_sets(
    members: [[u8; 20]; MAX_SIGNATURES],
    name_hashes: [Field; MAX_SIGNATURES],
) -> [u8; 32] {
    let mut buf = [0; 260];
    for i in 0..MAX_SIGNATURES {
        let hash_bytes = name_hashes[i].to_be_bytes::<32>();
        let offset = i * (20 + 32);
        for j in 0..20 {
            buf[offset + j] = members[i][j];
        }
        for j in 0..32 {
            buf[offset + 20 + j] = hash_bytes[j];
        }
    }
    keccak256(buf, 260)
}

// Main circuit entry point
pub fn main(
    rule: PolicyLine,
    user_action: UserAction,
    ctx: VerificationContext,
) -> pub PublicOutputs {
    assert(
        (rule.tx_type == TX_TYPE_TRANSFER) | (rule.tx_type == TX_TYPE_CONTRACT_CALL),
        "invalid transaction type",
    );
    assert(
        (rule.destination.kind == DEST_PATTERN_ANY)
            | (rule.destination.kind == DEST_PATTERN_GROUP)
            | (rule.destination.kind == DEST_PATTERN_ALLOWLIST)
            | (rule.destination.kind == DEST_PATTERN_EXACT),
        "invalid destination pattern",
    );
    assert(
        (rule.signer.kind == SIGNER_PATTERN_ANY)
            | (rule.signer.kind == SIGNER_PATTERN_EXACT)
            | (rule.signer.kind == SIGNER_PATTERN_GROUP)
            | (rule.signer.kind == SIGNER_PATTERN_THRESHOLD),
        "invalid signer pattern",
    );
    assert(
        (rule.asset.kind == ASSET_PATTERN_ANY) | (rule.asset.kind == ASSET_PATTERN_EXACT),
        "invalid asset pattern",
    );
    assert(
        (rule.signer.kind != SIGNER_PATTERN_THRESHOLD) | (rule.signer.threshold > 0),
        "zero signer threshold",
    );
    assert(
        (rule.tx_type != TX_TYPE_TRANSFER) | !rule.has_function_selector,
        "transfer rule has function selector",
    );
    assert(
        (rule.tx_type != TX_TYPE_CONTRACT_CALL)
            | (!rule.has_amount_max & (rule.asset.kind == ASSET_PATTERN_ANY)),
        "contract-call rule has transfer constraints",
    );

    let policy_hash = hash_policy_leaf(rule);

    assert(user_action.data_len <= MAX_CALLDATA_SIZE, "calldata length exceeds buffer");
    assert(user_action.signature_count <= MAX_SIGNATURES, "signature count exceeds buffer");
    assert(
        (user_action.value == 0) | (user_action.data_len == 0),
        "native value with calldata",
    );

    // Bytes outside the committed logical calldata cannot influence execution.
    for i in 0..MAX_CALLDATA_SIZE {
        assert(
            (i < user_action.data_len) | (user_action.data[i] == 0),
            "noncanonical calldata padding",
        );
    }

    let action_selector = slice_4_from_256(user_action.data, 0);
    let has_transfer_selector = (user_action.data_len >= 4) & (action_selector == TRANSFER_SELECTOR);
    assert(!has_transfer_selector | (user_action.data_len >= 68));

    let (tx_type, dest_addr, asset_addr, amount) = classify_user_action(user_action);
    let call_hash = hash_user_action(user_action);

    // (a) type
    assert(rule.tx_type == tx_type);

    // (b) destination
    assert(match_destination(rule.destination, dest_addr, ctx));

    // (c) signers
    assert(
        match_signer(rule.signer, user_action, ctx, call_hash),
        "signer policy not satisfied",
    );

    // (d) asset
    assert(match_asset(rule.asset, asset_addr));

    // (e) amount limit for transfers: use Field::lt + equality (no direct <= on Field)
    if tx_type == TX_TYPE_TRANSFER {
        if rule.has_amount_max {
            let amount_le_max: bool = (amount == rule.amount_max) | amount.lt(rule.amount_max);
            assert(amount_le_max);
        }
    }

    // (f/g) contract-call selector + wildcard asset for calls
    if tx_type == TX_TYPE_CONTRACT_CALL {
        if rule.has_function_selector {
            assert(user_action.data_len >= 4);
            let selector = slice_4_from_256(user_action.data, 0);
            assert(selector == rule.function_selector);
        }
        assert(rule.asset.kind == ASSET_PATTERN_ANY);
    }

    let groups_hash = hash_sets(ctx.groups, ctx.group_name_hashes);
    let allow_hash = hash_sets(ctx.allowlists, ctx.allowlist_name_hashes);

    PublicOutputs { call_hash, policy_hash, groups_hash, allow_hash }
}
