mod policy;

use policy::{
    ASSET_PATTERN_ANY, ASSET_PATTERN_EXACT, AssetPattern, DEST_PATTERN_ALLOWLIST, DEST_PATTERN_ANY,
    DEST_PATTERN_GROUP, DestinationPattern, MAX_CALLDATA_SIZE, MAX_SIGNATURES, PolicyLine,
    SIGNATURE_SIZE, SIGNER_PATTERN_ANY, SIGNER_PATTERN_EXACT, SIGNER_PATTERN_GROUP,
    SIGNER_PATTERN_THRESHOLD, SignerPattern, TX_TYPE_CONTRACT_CALL, TX_TYPE_TRANSFER, UserAction,
};

// --- Imports for Noir v1.0.0-beta.9 ---
use dep::keccak256::keccak256;
use std::ecdsa_secp256k1::verify_signature;
// --------------------------------------

// A struct to hold all the public outputs for the verifier.
pub struct PublicOutputs {
    call_hash: [u8; 32],
    policy_hash: [u8; 32],
    groups_hash: [u8; 32],
    allow_hash: [u8; 32],
}

// ERC-20 `transfer(address,uint256)` selector.
global TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
// Pseudo-address for native ETH.
global ETH_ASSET: [u8; 20] = [0; 20];

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

// Slices 32 bytes from a 256-byte calldata array.
fn slice_32_from_256(arr: [u8; 256], start: u32) -> [u8; 32] {
    let mut out = [0; 32];
    for i in 0..32 {
        out[i] = arr[start + i];
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

// Hash a UserAction for signing: to (20) || value(32 BE) || data[0..data_len].
fn hash_user_action(action: UserAction) -> [u8; 32] {
    // Build a fixed buffer and track the logical length.
    let mut buf = [0u8; 20 + 32 + MAX_CALLDATA_SIZE];
    let mut len: u32 = 0;

    // to (20)
    for i in 0..20 {
        buf[len] = action.to[i];
        len += 1;
    }

    // value --> 32-byte big-endian
    let val_be: [u8; 32] = action.value.to_be_bytes::<32>();
    for i in 0..32 {
        buf[len] = val_be[i];
        len += 1;
    }

    // data prefix up to action.data_len
    for i in 0..MAX_CALLDATA_SIZE {
        if i < action.data_len {
            buf[len] = action.data[i];
            len += 1;
        }
    }

    // External keccak256 requires (array, logical_length).
    let out: [u8; 32] = keccak256(buf, len);
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
        if name_hashes[i] == required_hash {
            if members[i] == address {
                found = true;
            }
        }
    }
    found
}

// Destination matches policy?
fn match_destination(
    pattern: DestinationPattern,
    addr: [u8; 20],
    ctx: VerificationContext,
) -> bool {
    let mut ok = false;
    if pattern.kind == DEST_PATTERN_ANY {
        ok = true;
    } else if pattern.kind == DEST_PATTERN_GROUP {
        ok = is_member(addr, ctx.groups, ctx.group_name_hashes, pattern.name_hash);
    } else if pattern.kind == DEST_PATTERN_ALLOWLIST {
        ok = is_member(
            addr,
            ctx.allowlists,
            ctx.allowlist_name_hashes,
            pattern.name_hash,
        );
    }
    ok
}

// Signer(s) match policy? (verify sigs, derive ETH address from pubkey, then match)
fn match_signer(pattern: SignerPattern, action: UserAction, ctx: VerificationContext) -> bool {
    let digest = hash_user_action(action);
    let mut res = false;

    if pattern.kind == SIGNER_PATTERN_ANY {
        res = action.signature_count > 0;
    } else if pattern.kind == SIGNER_PATTERN_EXACT {
        if action.signature_count == 1 {
            let sig = sig64_from_eth(action.signatures[0]);
            let px = ctx.signer_pubkeys_x[0];
            let py = ctx.signer_pubkeys_y[0];
            let verified = verify_signature(px, py, sig, digest);
            let mut cond = false;
            if verified {
                let who = eth_addr_from_pubkey(px, py);
                cond = who == pattern.address;
            }
            res = cond;
        } else {
            res = false;
        }
    } else if pattern.kind == SIGNER_PATTERN_GROUP {
        if action.signature_count == 1 {
            let sig = sig64_from_eth(action.signatures[0]);
            let px = ctx.signer_pubkeys_x[0];
            let py = ctx.signer_pubkeys_y[0];
            let verified = verify_signature(px, py, sig, digest);
            let mut cond = false;
            if verified {
                let who = eth_addr_from_pubkey(px, py);
                cond = is_member(
                    who,
                    ctx.groups,
                    ctx.group_name_hashes,
                    pattern.group_name_hash,
                );
            }
            res = cond;
        } else {
            res = false;
        }
    } else if pattern.kind == SIGNER_PATTERN_THRESHOLD {
        let mut valid: u32 = 0;
        for i in 0..MAX_SIGNATURES {
            let active = i < action.signature_count;

            // Get signature
            let raw_sig = action.signatures[i];
            let sig = sig64_from_eth(raw_sig);

            // Get pubkey
            let px = ctx.signer_pubkeys_x[i];
            let py = ctx.signer_pubkeys_y[i];

            // Verify signature with pubkey
            let ok = verify_signature(px, py, sig, digest);

            // Only accrue when both active and ok
            let contributes = active & ok;

            // Derive address from public key
            let signer_address = eth_addr_from_pubkey(px, py);
            let member = is_member(
                signer_address,
                ctx.groups,
                ctx.group_name_hashes,
                pattern.group_name_hash,
            );

            // Obtain contribution iif contributes * member = 1
            let value_contribution = contributes & member;
            valid += if value_contribution { 1 } else { 0 };
        }

        // Only valid if enough members
        res = valid >= (pattern.threshold as u32);
    }

    res
}

// Asset pattern match.
fn match_asset(pattern: AssetPattern, asset: [u8; 20]) -> bool {
    let mut ok = false;
    if pattern.kind == ASSET_PATTERN_ANY {
        ok = true;
    } else if pattern.kind == ASSET_PATTERN_EXACT {
        ok = pattern.address == asset;
    }
    ok
}

// Classify action --> (type, destination, asset, amount(Field))
fn classify_user_action(action: UserAction) -> (Field, [u8; 20], [u8; 20], Field) {
    let selector = slice_4_from_256(action.data, 0);
    let is_erc20_transfer = selector == TRANSFER_SELECTOR;

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
        let amount_be = slice_32_from_256(action.data, 36);
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

// Hashes a PolicyLine to create a commitment. This is a simplified serialization.
fn hash_policy_line(rule: PolicyLine) -> [u8; 32] {
    let name_hash_be: [u8; 32] = rule.destination.name_hash.to_be_bytes::<32>();
    keccak256(name_hash_be, 32)
}

// Hashes a list of members and their corresponding name hashes.
fn hash_sets(
    members: [[u8; 20]; MAX_SIGNATURES],
    name_hashes: [Field; MAX_SIGNATURES],
) -> [u8; 32] {
    let mut buf = [0; MAX_SIGNATURES * (20 + 32)];
    let mut len = 0;
    for i in 0..MAX_SIGNATURES {
        let hash_bytes = name_hashes[i].to_be_bytes::<32>();
        // Only include non-empty entries in the hash
        if name_hashes[i] != 0 {
            for j in 0..20 {
                buf[len] = members[i][j];
                len += 1;
            }
            for j in 0..32 {
                buf[len] = hash_bytes[j];
                len += 1;
            }
        }
    }
    keccak256(buf, len)
}

// Main circuit entry point
pub fn main(
    rule: PolicyLine,
    user_action: UserAction,
    ctx: VerificationContext,
) -> pub PublicOutputs {
    let (tx_type, dest_addr, asset_addr, amount) = classify_user_action(user_action);

    // (a) type
    assert(rule.tx_type == tx_type);

    // (b) destination
    assert(match_destination(rule.destination, dest_addr, ctx));

    // (c) signers
    assert(match_signer(rule.signer, user_action, ctx));

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
            let selector = slice_4_from_256(user_action.data, 0);
            assert(selector == rule.function_selector);
        }
        assert(rule.asset.kind == ASSET_PATTERN_ANY);
    }

    let call_hash = hash_user_action(user_action);
    let policy_hash = hash_policy_line(rule); // Simplified policy hash
    let groups_hash = hash_sets(ctx.groups, ctx.group_name_hashes);
    let allow_hash = hash_sets(ctx.allowlists, ctx.allowlist_name_hashes);

    PublicOutputs { call_hash, policy_hash, groups_hash, allow_hash }
}
