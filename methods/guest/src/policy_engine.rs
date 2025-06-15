// SPDX‑License‑Identifier: Apache‑2.0
// A minimal policy engine that evaluates on‑chain user actions against a
// configurable line‑by‑line policy.  The implementation follows the design
// brief dated 2025‑06‑14.

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec::Vec};
use bincode::Options;
use risc0_zkvm::guest::abort;
use std::collections::{HashMap, HashSet};
use zkguard_core::{
    ActionType, AssetPattern, DestinationPattern, Policy, SignerPattern, TxType, UserAction,
    ETH_ASSET,
};

/*───────────────────────────────────────────────────────────────────────────*
 *  Helper utilities                                                         *
 *───────────────────────────────────────────────────────────────────────────*/

/// ERC‑20 `transfer(address,uint256)` function selector (big‑endian).
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

// -------------------------------------------------------------------------
// helper: canonicalise a map of address-lists into a deterministic form
// -------------------------------------------------------------------------
pub fn canonicalise_lists(
    raw: HashMap<String, Vec<[u8; 20]>>,
) -> (BTreeMap<String, Vec<[u8; 20]>>, Vec<u8>) {
    let mut canon = BTreeMap::<String, Vec<[u8; 20]>>::new();
    for (k, mut v) in raw {
        v.sort();
        v.dedup();
        canon.insert(k, v);
    }
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&canon)
        .expect("serialise canonical lists");
    (canon, bytes)
}

// -------------------------------------------------------------------------
// helper: canonicalise the policy (sort by id, reject duplicates)
// -------------------------------------------------------------------------
pub fn canonicalise_policy(mut raw: Policy) -> (Policy, Vec<u8>) {
    raw.sort_by_key(|r| r.id);
    for win in raw.windows(2) {
        if win[0].id == win[1].id {
            abort("duplicate policy id");
        }
    }
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&raw)
        .expect("serialise canonical policy");
    (raw, bytes)
}

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
 *  The Policy Engine                                                        *
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
     *  1. Classify the user action                                         *
     *───────────────────────────────────────────────────────────────────────*/
    let (tx_type, dest_addr, asset_addr) = classify_user_action(user_action);

    /*───────────────────────────────────────────────────────────────────────*
     *  2. Iterate policy lines (top‑down)                                  *
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

        // (d) Asset pattern must match
        match &rule.asset {
            AssetPattern::Any => {}
            AssetPattern::Exact(addr) if addr == &asset_addr => {}
            _ => continue,
        }

        // (e) Contract calls must NOT specify an explicit asset
        if tx_type == TxType::ContractCall && !matches!(rule.asset, AssetPattern::Any) {
            continue;
        }

        // (f) Minimum threshold – not yet implemented (future work)

        // (g) Take the rule's action
        return matches!(rule.action, ActionType::Allow);
    }

    false // BLOCK by default, no matching rule found
}
