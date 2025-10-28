mod policy;

use policy::{
    ASSET_PATTERN_ANY, ASSET_PATTERN_EXACT, AssetPattern, DEST_PATTERN_ALLOWLIST, DEST_PATTERN_ANY,
    DEST_PATTERN_EXACT, DEST_PATTERN_GROUP, DestinationPattern, MAX_CALLDATA_SIZE, MAX_SIGNATURES,
    PolicyLine, SIGNATURE_SIZE, SIGNER_PATTERN_ANY, SIGNER_PATTERN_EXACT, SIGNER_PATTERN_GROUP,
    SIGNER_PATTERN_THRESHOLD, SignerPattern, TX_TYPE_CONTRACT_CALL, TX_TYPE_TRANSFER, UserAction,
};

// --- Imports for Noir v1.0.0-beta.9 ---
use dep::keccak256::keccak256;
use dep::sha256::digest;
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

// Maximum Merkle tree depth supported in-circuit.
// Adjust if your policy tree can exceed this depth.
global MAX_MERKLE_DEPTH: u32 = 64;
// Fixed-length serialization size for a PolicyLine leaf preimage.
// Layout (big-endian for Field values):
//   - tx_type (Field, 32)
//   - destination.kind (Field, 32)
//   - destination.name_hash (Field, 32)
//   - destination.address (20)
//   - signer.kind (Field, 32)
//   - signer.address (20)
//   - signer.group_name_hash (Field, 32)
//   - signer.threshold (1)
//   - asset.kind (Field, 32)
//   - asset.address (20)
//   - has_amount_max (1)
//   - amount_max (Field, 32)
//   - has_function_selector (1)
//   - function_selector (4)
global POLICY_LEAF_LEN: u32 = 291;

// Fixed-size Merkle path input for Noir.
pub struct MerklePathInput {
    // 0-based leaf index from the left
    leaf_index: u32,
    // Actual number of siblings in use (<= MAX_MERKLE_DEPTH)
    depth: u32,
    // Sibling hashes from bottom to top
    siblings: [[u8; 32]; MAX_MERKLE_DEPTH],
}

// Concatenate two 32-byte hashes into a single 64-byte buffer.
fn concat_32x2(left: [u8; 32], right: [u8; 32]) -> [u8; 64] {
    let mut out = [0u8; 64];
    for i in 0..32 {
        out[i] = left[i];
    }
    for i in 0..32 {
        out[32 + i] = right[i];
    }
    out
}

fn bool_to_byte(b: bool) -> u8 {
    if b {
        1
    } else {
        0
    }
}

// Serialize a PolicyLine into a fixed-length byte array (POLICY_LEAF_LEN),
// using big-endian encoding for Field values and fixed widths for all fields.
fn serialize_policy_line(rule: PolicyLine) -> [u8; POLICY_LEAF_LEN] {
    let mut out = [0u8; POLICY_LEAF_LEN];
    let mut p: u32 = 0;

    // tx_type (Field -> 32 bytes BE)
    let tx_be: [u8; 32] = rule.tx_type.to_be_bytes::<32>();
    for i in 0..32 {
        out[p] = tx_be[i];
        p += 1;
    }

    // destination.kind (Field -> 32)
    let dkind_be: [u8; 32] = rule.destination.kind.to_be_bytes::<32>();
    for i in 0..32 {
        out[p] = dkind_be[i];
        p += 1;
    }

    // destination.name_hash (Field -> 32)
    let dname_be: [u8; 32] = rule.destination.name_hash.to_be_bytes::<32>();
    for i in 0..32 {
        out[p] = dname_be[i];
        p += 1;
    }

    // destination.address (20)
    for i in 0..20 {
        out[p] = rule.destination.address[i];
        p += 1;
    }

    // signer.kind (Field -> 32)
    let skid_be: [u8; 32] = rule.signer.kind.to_be_bytes::<32>();
    for i in 0..32 {
        out[p] = skid_be[i];
        p += 1;
    }

    // signer.address (20)
    for i in 0..20 {
        out[p] = rule.signer.address[i];
        p += 1;
    }

    // signer.group_name_hash (Field -> 32)
    let sgrp_be: [u8; 32] = rule.signer.group_name_hash.to_be_bytes::<32>();
    for i in 0..32 {
        out[p] = sgrp_be[i];
        p += 1;
    }

    // signer.threshold (1)
    out[p] = rule.signer.threshold;
    p += 1;

    // asset.kind (Field -> 32)
    let akind_be: [u8; 32] = rule.asset.kind.to_be_bytes::<32>();
    for i in 0..32 {
        out[p] = akind_be[i];
        p += 1;
    }

    // asset.address (20)
    for i in 0..20 {
        out[p] = rule.asset.address[i];
        p += 1;
    }

    // has_amount_max (1)
    out[p] = bool_to_byte(rule.has_amount_max);
    p += 1;

    // amount_max (Field -> 32)
    let amt_be: [u8; 32] = rule.amount_max.to_be_bytes::<32>();
    for i in 0..32 {
        out[p] = amt_be[i];
        p += 1;
    }

    // has_function_selector (1)
    out[p] = bool_to_byte(rule.has_function_selector);
    p += 1;

    // function_selector (4)
    for i in 0..4 {
        out[p] = rule.function_selector[i];
        p += 1;
    }

    // p should equal POLICY_LEAF_LEN at this point
    out
}

// Verify inclusion of a leaf (already hashed with SHA-256) in a Merkle root using SHA-256 for internal nodes.
fn verify_merkle_membership(root: [u8; 32], leaf_hash: [u8; 32], path: MerklePathInput) -> bool {
    let mut acc = leaf_hash;
    let mut idx = path.leaf_index;

    // Iterate up to MAX_MERKLE_DEPTH but only use `path.depth` entries
    for i in 0..MAX_MERKLE_DEPTH {
        if i < path.depth {
            let sib = path.siblings[i];
            // If current index is even, node is left child: hash(acc || sib)
            // If odd, node is right child: hash(sib || acc)
            let combined: [u8; 64] = if (idx % 2) == 0u32 {
                concat_32x2(acc, sib)
            } else {
                concat_32x2(sib, acc)
            };
            acc = digest(combined);
            idx = idx / 2;
        }
    }

    acc == root
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

// Hash a UserAction for signing: from(20) || to(20) || value(32 BE) || data[0..data_len].
fn hash_user_action(action: UserAction) -> [u8; 32] {
    // Build a fixed buffer and track the logical length.
    let mut buf = [0u8; 20 + 20 + 32 + MAX_CALLDATA_SIZE];
    let mut len: u32 = 0;

    // from (20)
    for i in 0..20 {
        buf[len] = action.from[i];
        len += 1;
    }

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
    } else if pattern.kind == DEST_PATTERN_EXACT {
        ok = pattern.address == addr;
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
    // Merkle membership inputs
    policy_merkle_root: [u8; 32],
    policy_merkle_path: MerklePathInput,
) -> pub PublicOutputs {
    // Compute the policy leaf hash inside the circuit from the actual rule being enforced.
    let leaf_preimage = serialize_policy_line(rule);
    let computed_leaf_hash: [u8; 32] = digest(leaf_preimage);

    // Ensure the policy rule is a member of the committed Merkle root before any classification.
    let proof_is_valid =
        verify_merkle_membership(policy_merkle_root, computed_leaf_hash, policy_merkle_path);
    assert(proof_is_valid, "merkle-proof-invalid");

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
    let policy_hash = policy_merkle_root;
    let groups_hash = hash_sets(ctx.groups, ctx.group_name_hashes);
    let allow_hash = hash_sets(ctx.allowlists, ctx.allowlist_name_hashes);

    PublicOutputs { call_hash, policy_hash, groups_hash, allow_hash }
}
