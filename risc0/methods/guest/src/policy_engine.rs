// SPDX‑License‑Identifier: Apache‑2.0
// A minimal policy engine that evaluates on‑chain user actions against a
// configurable line‑by‑line policy.  The implementation follows the design
// brief dated 2025‑06‑14.

extern crate alloc;

use alloc::string::String;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use risc0_zkvm::guest::abort;
use sha3::{Digest, Keccak256};
use std::collections::{HashMap, HashSet};
use zkguard_core::{
    ActionType, AssetPattern, DestinationPattern, Policy, SignerPattern, TxType, UserAction,
    ETH_ASSET,
};
/*───────────────────────────────────────────────────────────────────────────*
 * Helper utilities                                                         *
 *───────────────────────────────────────────────────────────────────────────*/

/// ERC‑20 `transfer(address,uint256)` function selector (big‑endian).
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// Returns `true` if the calldata encodes an ERC‑20 `transfer`.
fn is_erc20_transfer(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == TRANSFER_SELECTOR
}

/// Attempts to parse an ERC‑20 `transfer` call.
/// Returns `(to, amount)` on success.
fn parse_erc20_transfer(data: &[u8]) -> Option<([u8; 20], u128)> {
    if !is_erc20_transfer(data) || data.len() < 4 + 32 + 32 {
        return None;
    }

    // `to` is stored right‑padded in the first parameter slot
    let mut to = [0u8; 20];
    to.copy_from_slice(&data[4 + 12..4 + 32]);

    // `amount` is stored as a 256‑bit big‑endian integer in the 2nd slot
    let mut amt_bytes = [0u8; 16]; // lowest 128‑bit slice (suffices for most tokens)
    amt_bytes.copy_from_slice(&data[4 + 32 + 16..4 + 64]);
    let amount = u128::from_be_bytes(amt_bytes);

    Some((to, amount))
}

/// Evaluate an address against a *destination* pattern.
fn match_destination(
    pattern: &DestinationPattern,
    addr: &[u8; 20],
    groups: &HashMap<String, HashSet<[u8; 20]>>,
    lists: &HashMap<String, HashSet<[u8; 20]>>,
) -> bool {
    match pattern {
        DestinationPattern::Any => true,
        DestinationPattern::Group(name) => groups.get(name).map_or(false, |set| set.contains(addr)),
        DestinationPattern::Allowlist(name) => {
            lists.get(name).map_or(false, |set| set.contains(addr))
        }
    }
}

fn hash_user_action(user_action: &UserAction) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(&user_action.to);
    h.update(&user_action.value.to_be_bytes());
    h.update(&user_action.data);
    h.finalize().into()
}

/// Evaluate the signer against the signer pattern.
fn match_signer(
    pattern: &SignerPattern,
    signer: &[u8; 20],
    groups: &HashMap<String, HashSet<[u8; 20]>>,
) -> bool {
    match pattern {
        SignerPattern::Any => true,
        SignerPattern::Exact(addr) => addr == signer,
        SignerPattern::Group(name) => groups.get(name).map_or(false, |set| set.contains(signer)),
    }
}

/// Verify that `ua.signature` is a *65-byte* (r‖s‖v) Ethereum-style sig and
/// that it was produced by `signer`.
fn match_signature(signer: &[u8; 20], ua: &UserAction) -> Result<(), &'static str> {
    /* 1. split r|s|v -----------------------------------------------------*/
    if ua.signature.len() != 65 {
        return Err("bad sig len");
    }
    let (rs, v) = ua.signature.split_at(64);

    let sig = Signature::try_from(rs).map_err(|_| "sig parse")?;
    let rec = RecoveryId::try_from(v[0]).map_err(|_| "rec id")?;

    /* 2. compute digest --------------------------------------------------*/
    // We sign the *pre-hashed* 32-byte canonical representation
    let digest = hash_user_action(ua);

    /* 3. recover pubkey --------------------------------------------------*/
    let vk = VerifyingKey::recover_from_prehash(
        &digest, // Pass the pre-computed hash
        &sig, rec,
    )
    .map_err(|_| "recover")?;

    /* 4. derive address --------------------------------------------------*/
    let pk = vk.to_encoded_point(false); // 04 || X || Y
    let mut h = Keccak256::new();
    h.update(&pk.as_bytes()[1..]); // drop 0x04
    let out = h.finalize();
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&out[12..]);

    if &addr == signer {
        Ok(())
    } else {
        Err("signer mismatch")
    }
}

fn match_asset(pattern: &AssetPattern, asset: &[u8; 20]) -> bool {
    match pattern {
        AssetPattern::Any => true,
        AssetPattern::Exact(addr) => addr == asset,
    }
}

fn classify_user_action(user_action: &UserAction) -> (TxType, [u8; 20], [u8; 20]) {
    if user_action.value > 0 || is_erc20_transfer(&user_action.data) {
        // Transfer
        if user_action.value > 0 && user_action.data.is_empty() {
            // Native ETH transfer (`CALL` with value, empty calldata)
            (TxType::Transfer, user_action.to, ETH_ASSET)
        } else {
            // ERC‑20 token transfer via `transfer(address,uint256)`
            match parse_erc20_transfer(&user_action.data) {
                Some((to, _amount)) => (TxType::Transfer, to, user_action.to), // `user_action.to` = token contract
                None => abort("malformed ERC-20 transfer data"),
            }
        }
    } else {
        // Contract call
        (TxType::ContractCall, user_action.to, ETH_ASSET) // `asset_addr` ignored for calls
    }
}

/*───────────────────────────────────────────────────────────────────────────*
 * The Policy Engine                                                        *
 *───────────────────────────────────────────────────────────────────────────*/

/// Evaluates a `UserAction` against the ordered `policy`.  Returns `true` if
/// the action is *allowed* and `false` otherwise.
pub fn run_policy_checks(
    policy: &Policy,
    groups: &HashMap<String, HashSet<[u8; 20]>>,
    allowlists: &HashMap<String, HashSet<[u8; 20]>>,
    user_action: &UserAction,
) -> bool {
    /*───────────────────────────────────────────────────────────────────────*
     * 1. Classify the user action                                         *
     *───────────────────────────────────────────────────────────────────────*/
    let (tx_type, dest_addr, asset_addr) = classify_user_action(user_action);

    /*───────────────────────────────────────────────────────────────────────*
     * 2. Iterate policy lines (top‑down)                                  *
     *───────────────────────────────────────────────────────────────────────*/
    // Verify that policy is ordered by `id` and has no duplicates
    if !policy.is_empty() {
        let mut prev_id = policy[0].id;
        // start at 1 because we already recorded element 0
        for line in &policy[1..] {
            if line.id <= prev_id {
                // Mis-ordered or duplicate ID ⇒ implicit block
                return false;
            }
            prev_id = line.id;
        }
    }

    for rule in policy {
        // (a) Tx‑type must match
        if rule.tx_type != tx_type {
            continue;
        }

        // (b) Destination pattern must match
        if !match_destination(&rule.destination, &dest_addr, groups, allowlists) {
            continue;
        }

        // (c) Signer pattern must match
        if !match_signer(&rule.signer, &user_action.signer, groups) {
            continue;
        }

        // (d) Match the signature with the signer
        match_signature(&user_action.signer, &user_action).expect("signature verification failed");

        // (e) Asset pattern must match
        if !match_asset(&rule.asset, &asset_addr) {
            continue;
        }

        // (f) Contract calls must NOT specify an explicit asset
        if tx_type == TxType::ContractCall && !matches!(rule.asset, AssetPattern::Any) {
            continue;
        }

        // (g) Minimum threshold – not yet implemented (future work)

        // (h) Take the rule's action
        return matches!(rule.action, ActionType::Allow);
    }

    false // BLOCK by default, no matching rule found
}
