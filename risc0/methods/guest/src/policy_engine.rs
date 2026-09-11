// SPDX-License-Identifier: Apache-2.0
// A minimal policy engine that evaluates on-chain user actions against a
// single, pre-verified policy line. The implementation follows the
// design brief dated 2025-06-14 and was updated for the ZKGuard architecture.

extern crate alloc;

use alloc::string::String;
use k256::ecdsa::{signature::hazmat::PrehashVerifier, RecoveryId, Signature, VerifyingKey};
use std::collections::BTreeMap;
// Use the standard `tiny-keccak` crate. The [patch] in Cargo.toml will accelerate it.
use tiny_keccak::{Hasher, Keccak};
use zkguard_core::{
    hash_user_action_for_signing, AssetPattern, DestinationPattern, PolicyLine, SignerPattern,
    TxType, UserAction, ETH_ASSET,
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

    // Policy limits are u128. Reject amounts outside that domain instead of
    // silently discarding the upper half of the ABI uint256.
    if data[4 + 32..4 + 32 + 16].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut amt_bytes = [0u8; 16];
    amt_bytes.copy_from_slice(&data[4 + 32 + 16..4 + 64]);
    let amount = u128::from_be_bytes(amt_bytes);

    Some((to, amount))
}

/// Evaluate an address against a *destination* pattern.
fn match_destination(
    pattern: &DestinationPattern,
    addr: &[u8; 20],
    groups: &BTreeMap<String, Vec<[u8; 20]>>,
    lists: &BTreeMap<String, Vec<[u8; 20]>>,
) -> bool {
    match pattern {
        DestinationPattern::Any => true,
        DestinationPattern::Exact(required_addr) => required_addr == addr,
        DestinationPattern::Group(name) => groups.get(name).is_some_and(|set| set.contains(addr)),
        DestinationPattern::Allowlist(name) => {
            lists.get(name).is_some_and(|set| set.contains(addr))
        }
    }
}

fn address_from_verifying_key(vk: &VerifyingKey) -> [u8; 20] {
    let pk = vk.to_encoded_point(false);
    let mut hasher = Keccak::v256();
    let mut keccak_hash = [0u8; 32];
    hasher.update(&pk.as_bytes()[1..]);
    hasher.finalize(&mut keccak_hash);

    let mut addr = [0u8; 20];
    addr.copy_from_slice(&keccak_hash[12..]);
    addr
}

fn verify_signer_with_key(
    digest: &[u8; 32],
    signature: &[u8],
    verifying_key: &[u8],
) -> Option<[u8; 20]> {
    if signature.len() != 65 {
        return None;
    }
    if verifying_key.len() != 65 {
        return None;
    }
    let sig = Signature::try_from(&signature[..64]).ok()?;
    let vk = VerifyingKey::from_sec1_bytes(verifying_key).ok()?;
    let recovery_id = match signature[64] {
        0 | 1 => RecoveryId::try_from(signature[64]).ok()?,
        27 | 28 => RecoveryId::try_from(signature[64] - 27).ok()?,
        _ => return None,
    };
    let recovered = VerifyingKey::recover_from_prehash(digest, &sig, recovery_id).ok()?;
    if recovered != vk {
        return None;
    }
    vk.verify_prehash(digest, &sig).ok()?;
    Some(address_from_verifying_key(&vk))
}

/// Evaluate the signer against the signer pattern.
fn match_signer(
    pattern: &SignerPattern,
    ua: &UserAction,
    groups: &BTreeMap<String, Vec<[u8; 20]>>,
    verifying_keys: &[Vec<u8>],
) -> bool {
    let digest = hash_user_action_for_signing(ua);
    if ua.signatures.len() != verifying_keys.len() {
        return false;
    }

    match pattern {
        SignerPattern::Any => {
            ua.signatures
                .iter()
                .zip(verifying_keys.iter())
                .any(|(sig, verifying_key)| {
                    verify_signer_with_key(&digest, sig, verifying_key).is_some()
                })
        }
        SignerPattern::Exact(required_signer) => {
            if ua.signatures.len() != 1 {
                return false;
            }
            verify_signer_with_key(&digest, &ua.signatures[0], &verifying_keys[0])
                .is_some_and(|signer| &signer == required_signer)
        }
        SignerPattern::Group(name) => {
            if ua.signatures.len() != 1 {
                return false;
            }
            let group = groups.get(name).expect("missing group");
            verify_signer_with_key(&digest, &ua.signatures[0], &verifying_keys[0])
                .is_some_and(|signer| group.contains(&signer))
        }
        SignerPattern::Threshold { group, threshold } => {
            if *threshold == 0 {
                return false;
            }
            let required_group = groups.get(group).expect("missing group for threshold");
            let mut valid_signers: Vec<[u8; 20]> = Vec::new();

            for (sig, verifying_key) in ua.signatures.iter().zip(verifying_keys.iter()) {
                if let Some(signer) = verify_signer_with_key(&digest, sig, verifying_key) {
                    if required_group.contains(&signer) && !valid_signers.contains(&signer) {
                        valid_signers.push(signer);
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

fn classify_user_action(user_action: &UserAction) -> Option<(TxType, [u8; 20], [u8; 20], u128)> {
    if user_action.value > 0 && !user_action.data.is_empty() {
        return None;
    }
    if user_action.value > 0 || is_erc20_transfer(&user_action.data) {
        // Transfer
        if user_action.value > 0 && user_action.data.is_empty() {
            // Native ETH transfer (`CALL` with value, empty calldata)
            Some((
                TxType::Transfer,
                user_action.to,
                ETH_ASSET,
                user_action.value,
            ))
        } else {
            // ERC-20 token transfer via `transfer(address,uint256)`
            parse_erc20_transfer(&user_action.data)
                .map(|(to, amount)| (TxType::Transfer, to, user_action.to, amount))
        }
    } else {
        // Contract call
        Some((TxType::ContractCall, user_action.to, ETH_ASSET, 0))
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
    groups: &BTreeMap<String, Vec<[u8; 20]>>,
    allowlists: &BTreeMap<String, Vec<[u8; 20]>>,
    user_action: &UserAction,
    verifying_keys: &[Vec<u8>],
) -> bool {
    // 1. Classify the user action to determine its type, destination, and asset.
    let Some((tx_type, dest_addr, asset_addr, amount)) = classify_user_action(user_action) else {
        return false;
    };

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
    if !match_signer(&rule.signer, user_action, groups, verifying_keys) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use k256::ecdsa::SigningKey;

    fn sign_action(mut action: UserAction, signing_key: &SigningKey) -> UserAction {
        let digest = hash_user_action_for_signing(&action);
        let (signature, recovery_id) = signing_key.sign_prehash_recoverable(&digest).unwrap();
        let mut encoded = signature.to_bytes().to_vec();
        encoded.push(recovery_id.to_byte());
        action.signatures.push(encoded);
        action
    }

    fn contract_call(signing_key: &SigningKey) -> UserAction {
        sign_action(
            UserAction {
                from: [0x11; 20],
                to: [0x22; 20],
                value: 0,
                nonce: 7,
                data: vec![0x12, 0x34, 0x56, 0x78],
                signatures: Vec::new(),
            },
            signing_key,
        )
    }

    fn token_transfer(signing_key: &SigningKey, upper_amount_byte: u8, value: u128) -> UserAction {
        let mut data = vec![0u8; 68];
        data[..4].copy_from_slice(&TRANSFER_SELECTOR);
        data[16..36].copy_from_slice(&[0x22; 20]);
        data[51] = upper_amount_byte;
        data[67] = 1;
        sign_action(
            UserAction {
                from: [0x11; 20],
                to: [0x44; 20],
                value,
                nonce: 7,
                data,
                signatures: Vec::new(),
            },
            signing_key,
        )
    }

    fn verifying_key_bytes(signing_key: &SigningKey) -> Vec<u8> {
        signing_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    #[test]
    fn any_signer_requires_a_valid_signature() {
        let signing_key = SigningKey::from_slice(&[0x33; 32]).unwrap();
        let wrong_key = SigningKey::from_slice(&[0x44; 32]).unwrap();
        let action = contract_call(&signing_key);
        let groups = BTreeMap::new();

        assert!(match_signer(
            &SignerPattern::Any,
            &action,
            &groups,
            &[verifying_key_bytes(&signing_key)],
        ));
        assert!(!match_signer(
            &SignerPattern::Any,
            &action,
            &groups,
            &[verifying_key_bytes(&wrong_key)],
        ));
    }

    #[test]
    fn ethereum_recovery_id_must_match_verifying_key() {
        let signing_key = SigningKey::from_slice(&[0x33; 32]).unwrap();
        let mut action = contract_call(&signing_key);
        let verifying_keys = [verifying_key_bytes(&signing_key)];
        let groups = BTreeMap::new();

        assert!(match_signer(
            &SignerPattern::Any,
            &action,
            &groups,
            &verifying_keys
        ));
        let recovery_id = action.signatures[0][64];
        action.signatures[0][64] = recovery_id + 27;
        assert!(match_signer(
            &SignerPattern::Any,
            &action,
            &groups,
            &verifying_keys
        ));
        action.signatures[0][64] = recovery_id ^ 1;
        assert!(!match_signer(
            &SignerPattern::Any,
            &action,
            &groups,
            &verifying_keys
        ));
        action.signatures[0][64] = 255;
        assert!(!match_signer(
            &SignerPattern::Any,
            &action,
            &groups,
            &verifying_keys
        ));
    }

    #[test]
    fn rejects_erc20_amount_above_u128() {
        let signing_key = SigningKey::from_slice(&[0x33; 32]).unwrap();
        let action = token_transfer(&signing_key, 1, 0);
        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer,
            destination: DestinationPattern::Exact([0x22; 20]),
            signer: SignerPattern::Any,
            asset: AssetPattern::Exact([0x44; 20]),
            amount_max: Some(1),
            function_selector: None,
        };
        assert!(!run_policy_checks(
            &rule,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &action,
            &[verifying_key_bytes(&signing_key)],
        ));
    }

    #[test]
    fn rejects_native_value_with_calldata() {
        let signing_key = SigningKey::from_slice(&[0x33; 32]).unwrap();
        let action = token_transfer(&signing_key, 0, 1);
        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer,
            destination: DestinationPattern::Exact([0x22; 20]),
            signer: SignerPattern::Any,
            asset: AssetPattern::Exact([0x44; 20]),
            amount_max: Some(1),
            function_selector: None,
        };
        assert!(!run_policy_checks(
            &rule,
            &BTreeMap::new(),
            &BTreeMap::new(),
            &action,
            &[verifying_key_bytes(&signing_key)],
        ));
    }

    #[test]
    fn rejects_zero_signer_threshold() {
        let action = UserAction {
            from: [0x11; 20],
            to: [0x22; 20],
            value: 0,
            nonce: 7,
            data: vec![0x12, 0x34, 0x56, 0x78],
            signatures: Vec::new(),
        };
        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::ContractCall,
            destination: DestinationPattern::Any,
            signer: SignerPattern::Threshold {
                group: "Owners".into(),
                threshold: 0,
            },
            asset: AssetPattern::Any,
            amount_max: None,
            function_selector: None,
        };
        let groups = BTreeMap::from([("Owners".into(), Vec::new())]);
        assert!(!run_policy_checks(
            &rule,
            &groups,
            &BTreeMap::new(),
            &action,
            &[],
        ));
    }
}
