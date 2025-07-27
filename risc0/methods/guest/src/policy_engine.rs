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
 * Helper utilities (unchanged)                                             *
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

    hasher.update(&user_action.to);
    hasher.update(&user_action.value.to_be_bytes());
    hasher.update(&user_action.data);

    hasher.finalize(&mut output);
    output
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
/// that it was produced by `signer`. Aborts the proof on failure.
fn verify_signature(signer: &[u8; 20], ua: &UserAction) {
    /* 1. split r|s|v -----------------------------------------------------*/
    if ua.signature.len() != 65 {
        abort("bad sig len");
    }
    let (rs, v) = ua.signature.split_at(64);

    let Ok(sig) = Signature::try_from(rs) else {
        abort("sig parse")
    };
    let Ok(rec) = RecoveryId::try_from(v[0]) else {
        abort("rec id")
    };

    /* 2. compute digest --------------------------------------------------*/
    let digest = hash_user_action(ua);

    /* 3. recover pubkey --------------------------------------------------*/
    // CHANGE: Pass a simple reference `&digest` instead of `&digest.into()`.
    let Ok(vk) = VerifyingKey::recover_from_prehash(&digest, &sig, rec) else {
        abort("recover failed")
    };

    /* 4. derive address --------------------------------------------------*/
    let pk = vk.to_encoded_point(false); // 04 || X || Y

    // Use the standard `tiny-keccak` API for address derivation.
    let mut hasher = Keccak::v256();
    let mut keccak_hash = [0u8; 32];
    hasher.update(&pk.as_bytes()[1..]); // drop 0x04 prefix
    hasher.finalize(&mut keccak_hash);

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&keccak_hash[12..]);

    if &addr != signer {
        abort("signer mismatch")
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
            // ERC-20 token transfer via `transfer(address,uint256)`
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
    let (tx_type, dest_addr, asset_addr) = classify_user_action(user_action);

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

    // (c) The action's signer must match the rule's signer pattern.
    if !match_signer(&rule.signer, &user_action.signer, groups) {
        return false;
    }

    // (d) The signature must be valid for the claimed signer.
    // This is a critical check and will abort the entire proof on failure.
    verify_signature(&user_action.signer, user_action);

    // (e) The action's asset must match the rule's asset pattern.
    if !match_asset(&rule.asset, &asset_addr) {
        return false;
    }

    // (f) A special case: ContractCall rules should not specify a specific asset.
    if tx_type == TxType::ContractCall && !matches!(rule.asset, AssetPattern::Any) {
        return false;
    }

    // If all checks passed, the user action is allowed by this rule.
    true
}