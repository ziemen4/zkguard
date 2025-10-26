// SPDX-License-Identifier: Apache-2.0
// A minimal policy engine that evaluates on-chain user actions against a
// single, pre-verified policy line. The implementation follows the
// design brief dated 2025-06-14 and was updated for the ZKGuard architecture.

extern crate alloc;

use alloc::string::String;
use k256::ecdsa::{RecoveryId, Signature, VerifyingKey};
use risc0_zkvm::guest::abort;
use std::collections::{HashMap, HashSet};
// Use the standard `tiny-keccak` crate. The [patch] in Cargo.toml will accelerate it.
use tiny_keccak::{Hasher, Keccak};
use zkguard_core::{
    AssetPattern, DestinationPattern, PolicyLine, SignerPattern, TxType, UserAction, ETH_ASSET,
};

/*───────────────────────────────────────────────────────────────────────────*
 * Helper utilities                          *
 *───────────────────────────────────────────────────────────────────────────*/

/// ERC-20 `transfer(address,uint256)` function selector (big-endian).
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

/// Returns `true` if the calldata encodes an ERC-20 `transfer`.
fn is_erc20_transfer(data: &[u8]) -> bool {
    data.len() >= 4 && data[..4] == TRANSFER_SELECTOR
}

/// Attempts to parse an ERC-20 `transfer` call.
/// Returns `(to, amount)` on success.
fn parse_erc20_transfer(data: &[u8]) -> Option<([u8; 20], u128)> {
    if !is_erc20_transfer(data) || data.len() < 4 + 32 + 32 {
        return None;
    }

    // `to` is stored right-padded in the first parameter slot
    let mut to = [0u8; 20];
    to.copy_from_slice(&data[4 + 12..4 + 32]);

    // `amount` is stored as a 256-bit big-endian integer in the 2nd slot
    let mut amt_bytes = [0u8; 16]; // lowest 128-bit slice (suffices for most tokens)
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
        DestinationPattern::Exact(required_addr) => required_addr == addr,
        DestinationPattern::Group(name) => groups.get(name).map_or(false, |set| set.contains(addr)),
        DestinationPattern::Allowlist(name) => {
            lists.get(name).map_or(false, |set| set.contains(addr))
        }
    }
}

// Use the standard streaming API from `tiny-keccak`.
fn hash_user_action(user_action: &UserAction) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];

    hasher.update(&user_action.from);
    hasher.update(&user_action.to);
    hasher.update(&user_action.value.to_be_bytes());
    hasher.update(&user_action.data);
    hasher.update(&user_action.nonce.to_be_bytes());

    hasher.finalize(&mut output);
    output
}

/// Recovers the signer's address from a 65-byte (r||s||v) Ethereum-style
/// Recovers the signer's address from a 65-byte (r||s||v) Ethereum-style
/// signature. Returns `None` on failure.
fn recover_signer(digest: &[u8; 32], signature: &[u8]) -> Option<[u8; 20]> {
    if signature.len() != 65 {
        return None; // Invalid signature length
    }
    let (rs, v_byte) = signature.split_at(64);
    let sig = Signature::try_from(rs).ok()?;

    // Normalize v to 0 or 1 for k256, from 27/28 in Ethereum
    let v = match v_byte[0] {
        27 => 0,
        28 => 1,
        v_val => v_val,
    };

    let rec_id = RecoveryId::try_from(v).ok()?;

    let vk = VerifyingKey::recover_from_prehash(digest, &sig, rec_id).ok()?;
    let pk = vk.to_encoded_point(false);

    let mut hasher = Keccak::v256();
    let mut keccak_hash = [0u8; 32];
    hasher.update(&pk.as_bytes()[1..]);
    hasher.finalize(&mut keccak_hash);

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&keccak_hash[12..]);
    Some(addr)
}

/// Evaluate the signer against the signer pattern.
fn match_signer(
    pattern: &SignerPattern,
    ua: &UserAction,
    groups: &HashMap<String, HashSet<[u8; 20]>>,
) -> bool {
    let digest = hash_user_action(ua);

    match pattern {
        SignerPattern::Any => !ua.signatures.is_empty(), // Any signature is fine, but there must be at least one.
        SignerPattern::Exact(required_signer) => {
            if ua.signatures.len() != 1 {
                return false;
            }
            recover_signer(&digest, &ua.signatures[0])
                .map_or(false, |signer| &signer == required_signer)
        }
        SignerPattern::Group(name) => {
            if ua.signatures.len() != 1 {
                return false;
            }
            let group = groups.get(name).expect("missing group");
            recover_signer(&digest, &ua.signatures[0])
                .map_or(false, |signer| group.contains(&signer))
        }
        SignerPattern::Threshold { group, threshold } => {
            let required_group = groups.get(group).expect("missing group for threshold");
            let mut valid_signers = HashSet::new();

            for sig in &ua.signatures {
                if let Some(signer) = recover_signer(&digest, sig) {
                    if required_group.contains(&signer) {
                        valid_signers.insert(signer);
                    }
                }
            }
            valid_signers.len() >= *threshold as usize
        }
    }
}

fn match_asset(pattern: &AssetPattern, asset: &[u8; 20]) -> bool {
    match pattern {
        AssetPattern::Any => true,
        AssetPattern::Exact(addr) => addr == asset,
    }
}

fn classify_user_action(user_action: &UserAction) -> (TxType, [u8; 20], [u8; 20], u128) {
    if user_action.value > 0 || is_erc20_transfer(&user_action.data) {
        // Transfer
        if user_action.value > 0 && user_action.data.is_empty() {
            // Native ETH transfer (`CALL` with value, empty calldata)
            (
                TxType::Transfer,
                user_action.to,
                ETH_ASSET,
                user_action.value,
            )
        } else {
            // ERC-20 token transfer via `transfer(address,uint256)`
            match parse_erc20_transfer(&user_action.data) {
                Some((to, amount)) => (TxType::Transfer, to, user_action.to, amount), // `user_action.to` = token contract
                None => abort("malformed ERC-20 transfer data"),
            }
        }
    } else {
        // Contract call
        (TxType::ContractCall, user_action.to, ETH_ASSET, 0) // `asset_addr` ignored for calls
    }
}

/*───────────────────────────────────────────────────────────────────────────*
 * The Policy Engine (Refactored)                                           *
 *───────────────────────────────────────────────────────────────────────────*/

/// Evaluates a `UserAction` against a single `PolicyLine`. Returns `true` if
/// the action is fully compliant with the rule.
///
/// This function is the core of the ZK-proof. It confirms that the user's
/// action precisely matches the single "allow" rule provided by the host.
pub fn run_policy_checks(
    rule: &PolicyLine,
    groups: &HashMap<String, HashSet<[u8; 20]>>,
    allowlists: &HashMap<String, HashSet<[u8; 20]>>,
    user_action: &UserAction,
) -> bool {
    // 1. Classify the user action to determine its type, destination, and asset.
    let (tx_type, dest_addr, asset_addr, amount) = classify_user_action(user_action);

    // 2. The host claims this `rule` allows the `user_action`. We now verify this claim.
    // Each check must pass for the action to be considered valid under this rule.

    // (a) Tx-type must match the rule.
    if rule.tx_type != tx_type {
        return false;
    }

    // (b) Destination address must match the rule's destination pattern.
    if !match_destination(&rule.destination, &dest_addr, groups, allowlists) {
        return false;
    }

    // (c) The action's signer(s) must match the rule's signer pattern.
    // This check now includes signature verification.
    if !match_signer(&rule.signer, user_action, groups) {
        return false;
    }

    // (d) The action's asset must match the rule's asset pattern.
    if !match_asset(&rule.asset, &asset_addr) {
        return false;
    }

    // (e) For transfers, if an amount_max is specified, check it.
    if tx_type == TxType::Transfer {
        if let Some(max_amount) = rule.amount_max {
            if amount > max_amount {
                return false; // Amount exceeds the maximum allowed by the policy
            }
        }
    }

    // (f) If the action is a contract call, check the function selector if specified.
    if tx_type == TxType::ContractCall {
        if let Some(function_selector) = rule.function_selector {
            if user_action.data.len() < 4 || user_action.data[..4] != function_selector {
                return false; // Function selector doesn't match the policy
            }
        }
    }

    // (g) A special case: ContractCall rules should not specify a specific asset.
    if tx_type == TxType::ContractCall && !matches!(rule.asset, AssetPattern::Any) {
        return false;
    }

    // If all checks passed, the user action is allowed by this rule.
    true
}
