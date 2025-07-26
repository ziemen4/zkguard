extern crate alloc;
use alloc::vec::Vec;

use bincode::Options;
use risc0_zkvm::guest::{entry, env};
use std::collections::{BTreeMap, HashMap, HashSet};
use zkguard_core::{keccak256, MerklePath, PolicyLine, UserAction};

use zkguard_guest::policy_engine::run_policy_checks;

// TODO: benchmark whether *rejecting* non-canonical inputs and failing the
//       proof is cheaper than the in-circuit canonicalisation we do here.
/// Canonicalises a map of lists: sorts addresses ascending (dedup) and uses
/// a `BTreeMap` so keys are ordered.  Returns `(canonical, bytes)` where
/// `bytes` is the bincode serialization of the canonical structure.
fn canonicalise_lists(
    raw: HashMap<String, Vec<[u8; 20]>>,
) -> (BTreeMap<String, Vec<[u8; 20]>>, Vec<u8>) {
    use bincode::Options;
    let mut canon: BTreeMap<String, Vec<[u8; 20]>> = BTreeMap::new();
    for (k, mut v) in raw {
        v.sort();
        v.dedup();
        canon.insert(k, v);
    }
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&canon)
        .expect("canonical serialise");
    (canon, bytes)
}

/// Verifies a Merkle proof for a given leaf against a root.
///
/// It computes the Merkle root from a leaf, its index, and a path of sibling
/// hashes. The result is then compared against the expected root. This function
/// assumes the `MerklePath` struct contains the leaf's index and its sibling hashes.
///
/// # Arguments
/// * `root` - The expected Merkle root.
/// * `leaf_bytes` - The serialized bytes of the leaf node (the `PolicyLine`).
/// * `proof` - The `MerklePath` containing the `leaf_index` and `siblings`.
///
/// # Returns
/// `true` if the computed root matches the expected root, `false` otherwise.
fn verify_merkle_proof(root: &[u8; 32], leaf_bytes: &[u8], proof: &MerklePath) -> bool {
    let mut computed_hash = keccak256(leaf_bytes);
    let mut current_index = proof.leaf_index;

    for sibling_hash in &proof.siblings {
        let mut combined = Vec::with_capacity(64);
        if current_index % 2 == 0 {
            // Current node is a left child, sibling is on the right
            combined.extend_from_slice(&computed_hash);
            combined.extend_from_slice(sibling_hash);
        } else {
            // Current node is a right child, sibling is on the left
            combined.extend_from_slice(sibling_hash);
            combined.extend_from_slice(&computed_hash);
        }
        computed_hash = keccak256(&combined);
        current_index /= 2; // Move up to the parent level
    }

    computed_hash == *root
}

// ================================================================
// Implements a line‑by‑line policy evaluator for wallet actions and
// exposes a `main` that the ZKP wrapper invokes.  Frames sent by the
// host arrive in the following order:
//   0. Merkle root   (32 bytes)
//   1. UserAction    (bincode, fixint)
//   2. Policy line   (bincode, fixint)
//   3. Merkle path   (bincode, fixint)
//   4. Groups        (HashMap<String, Vec<[u8;20]>>)
//   5. Allow‑lists   (HashMap<String, Vec<[u8;20]>>)
// ------------------------------------------------
// Any failure to meet policy results in `assert!` which aborts the
// circuit.  On success, we commit the following hashes so the wrapper
// can pin the exact inputs used for verification:
//   • call‑hash      – keccak256(calldata)
//   • policy‑hash    – keccak256(serialised Policy)
//   • groups‑hash    – keccak256(serialised Groups)
//   • allow‑hash     – keccak256(serialised Allow‑lists)
entry!(main);

fn main() {
    // ──────────────────────────────────────────────────────────────────────
    // 0. Merkle‑root (32 bytes)
    // ──────────────────────────────────────────────────────────────────────
    env::log("[ZKGuard] Reading Merkle root from the prover environment...");
    let root_bytes: Vec<u8> = env::read_frame();
    env::log(&format!(
        "[ZKGuard] Policy Merkle root length in bytes: {:?}",
        root_bytes.len()
    ));
    let policy_merkle_root: [u8; 32] = root_bytes
        .clone()
        .try_into()
        .expect("expected 32 bytes for Merkle root");
    env::log(&format!(
        "[ZKGuard] Policy Merkle root: {:?}",
        policy_merkle_root
    ));

    // ──────────────────────────────────────────────────────────────────────
    // 1. UserAction
    // ──────────────────────────────────────────────────────────────────────
    let bytes: Vec<u8> = env::read_frame();
    println!("[ZKGuard] User action length in bytes: {:?}", bytes.len());
    let user_action: UserAction = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&bytes)
        .expect("deserialize UserAction");
    println!("[ZKGuard] User action: {:?}", user_action);
    // ──────────────────────────────────────────────────────────────────────
    // 2. Allow‑list leaf – this is the single policy line to check
    // ──────────────────────────────────────────────────────────────────────
    let bytes_policy_line: Vec<u8> = env::read_frame();
    println!(
        "[ZKGuard] Policy line length in bytes: {:?}",
        bytes_policy_line.len()
    );
    let policy_line: PolicyLine = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&bytes_policy_line)
        .expect("deserialize PolicyLine");
    println!("[ZKGuard] Policy line: {:?}", policy_line);
    // ──────────────────────────────────────────────────────────────────────
    // 3. Merkle path
    // ──────────────────────────────────────────────────────────────────────
    let path_bytes: Vec<u8> = env::read_frame();
    println!(
        "[ZKGuard] Merkle path length in bytes: {:?}",
        path_bytes.len()
    );
    let policy_merkle_proof = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize::<MerklePath>(&path_bytes)
        .expect("deserialize MerklePath");
    println!("[ZKGuard] Merkle path: {:?}", policy_merkle_proof);

    // ──────────────────────────────────────────────────────────────────────
    // 4. Groups
    // ──────────────────────────────────────────────────────────────────────
    let groups_raw_bytes: Vec<u8> = env::read_frame();
    println!(
        "[ZKGuard] Groups length in bytes: {:?}",
        groups_raw_bytes.len()
    );
    let raw_groups: HashMap<String, Vec<[u8; 20]>> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&groups_raw_bytes)
        .expect("deserialize Groups");
    let (groups_canon, groups_bytes) = canonicalise_lists(raw_groups);
    let groups_sets: HashMap<String, HashSet<[u8; 20]>> = groups_canon
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
        .collect();
    println!("[ZKGuard] Groups: {:?}", groups_sets);

    // ──────────────────────────────────────────────────────────────────────
    // 5. Allow‑lists
    // ──────────────────────────────────────────────────────────────────────
    let allow_raw_bytes: Vec<u8> = env::read_frame();
    println!(
        "[ZKGuard] Allow-lists length in bytes: {:?}",
        allow_raw_bytes.len()
    );
    let raw_allow: HashMap<String, Vec<[u8; 20]>> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&allow_raw_bytes)
        .expect("deserialize Allow-lists");
    let (allow_canon, allow_bytes) = canonicalise_lists(raw_allow);
    let allow_sets: HashMap<String, HashSet<[u8; 20]>> = allow_canon
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
        .collect();
    println!("[ZKGuard] Allow-lists: {:?}", allow_sets);

    // ──────────────────────────────────────────────────────────────────────
    // 6. Verify the Merkle proof for the policy line
    // ──────────────────────────────────────────────────────────────────────
    let proof_is_valid = verify_merkle_proof(
        &policy_merkle_root,
        &bytes_policy_line,
        &policy_merkle_proof,
    );
    assert!(proof_is_valid, "merkle-proof-invalid");

    // ──────────────────────────────────────────────────────────────────────
    // 7. Verify the user action against the policy line
    // ──────────────────────────────────────────────────────────────────────
    let allowed = run_policy_checks(&policy_line, &groups_sets, &allow_sets, &user_action);
    assert!(allowed, "policy-violation");

    // ──────────────────────────────────────────────────────────────────────
    // 8. Commit the hashes of the inputs used for verification
    // ──────────────────────────────────────────────────────────────────────
    let call_hash = keccak256(&user_action.data);
    let root = root_bytes
        .try_into()
        .expect("expected 32 bytes for Merkle root");
    let groups_hash = keccak256(&groups_bytes);
    let allow_hash = keccak256(&allow_bytes);

    println!("[ZKGuard] Call hash: {:?}", call_hash);
    println!("[ZKGuard] Policy Merkle root: {:?}", root);
    println!("[ZKGuard] Groups hash: {:?}", groups_hash);
    println!("[ZKGuard] Allow-list hash: {:?}", allow_hash);
    let hashes: Vec<[u8; 32]> = vec![call_hash, root, groups_hash, allow_hash];
    println!("[ZKGuard] Committing hashes: {:?}", hashes);
    env::commit(&hashes);
}

// Tests
#[cfg(test)]
mod tests {
    use super::run_policy_checks;
    use std::collections::{HashMap, HashSet};

    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::rand_core::OsRng;
    use sha3::{Digest, Keccak256};
    use zkguard_core::{
        AssetPattern, DestinationPattern, PolicyLine, SignerPattern, TxType, UserAction,
    };

    /*─────────────────  helpers  ─────────────────*/

    // Helper to hash the UserAction exactly like the guest code
    fn hash_user_action(ua: &UserAction) -> [u8; 32] {
        // This must match the signature recovery logic in `run_policy_checks`
        let mut h = Keccak256::new();
        h.update(&ua.to);
        h.update(&ua.value.to_be_bytes());
        h.update(&ua.data);
        h.finalize().into()
    }

    /// Generate (signer-addr, signature-bytes, signing-key)
    fn make_sig(user_action: &UserAction) -> ([u8; 20], Vec<u8>, SigningKey) {
        let sk = SigningKey::random(&mut OsRng);
        let pk_bytes = sk.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec();
        let signer_address: [u8; 20] = Keccak256::digest(&pk_bytes)[12..].try_into().unwrap();

        let message_hash = hash_user_action(&user_action);
        let Ok((signature, recovery_id)) = sk.sign_prehash_recoverable(&message_hash) else {
            panic!("Failed to sign user action");
        };

        let mut sig_bytes = signature.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte());

        (signer_address, sig_bytes, sk)
    }

    /// Same maps for every test unless overridden
    fn empty_maps() -> (
        HashMap<String, HashSet<[u8; 20]>>,
        HashMap<String, HashSet<[u8; 20]>>,
    ) {
        (HashMap::new(), HashMap::new())
    }

    /// Wrap the engine, treating *panic* as a “block”.
    /// This now tests if a *single rule* allows the action, reflecting the new ZK logic.
    fn is_allowed(
        rule: &PolicyLine,
        g: &HashMap<String, HashSet<[u8; 20]>>,
        a: &HashMap<String, HashSet<[u8; 20]>>,
        ua: &UserAction,
    ) -> bool {
        // We expect `run_policy_checks` to find a matching rule in the slice.
        // In the refactored tests, the slice `&[*rule]` contains just the one rule.
        std::panic::catch_unwind(|| run_policy_checks(rule, g, a, ua)).unwrap_or(false)
    }

    /// Tiny address helper
    fn addr(b: u8) -> [u8; 20] {
        [b; 20]
    }

    /*─────────────────  tests  ─────────────────*/

    // ✅ Happy Path: A valid transfer that matches the policy should be allowed.
    #[test]
    fn happy_path_transfer_allowed() {
        let mut ua = UserAction {
            to: addr(0x10), // Destination is in GroupA
            value: 1,
            data: Vec::new(),
            signer: [0u8; 20],
            signature: Vec::new(),
        };
        let (signer, sig, _sk) = make_sig(&ua);
        ua.signer = signer; // Signer is exact
        ua.signature = sig;

        let mut groups = HashMap::<String, HashSet<[u8; 20]>>::new();
        groups.insert("GroupA".into(), HashSet::from([addr(0x10)]));

        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer,
            destination: DestinationPattern::Group("GroupA".into()),
            signer: SignerPattern::Exact(signer),
            asset: AssetPattern::Any,
        };

        let allow = HashMap::new();
        assert!(is_allowed(&rule, &groups, &allow, &ua));
    }

    // 1 ─ Transfer rule but action is ContractCall  → Block
    #[test]
    fn transfer_rule_vs_contract_call() {
        let mut ua = UserAction {
            to: addr(0x02),
            value: 0,
            data: vec![0xaa], // this makes it a contract call
            signer: [0u8; 20],
            signature: Vec::new(),
        };
        let (signer, sig, _sk) = make_sig(&ua);
        ua.signer = signer;
        ua.signature = sig;

        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer, // Rule expects a transfer
            destination: DestinationPattern::Any,
            signer: SignerPattern::Exact(signer),
            asset: AssetPattern::Any,
        };

        let (g, a) = empty_maps();
        assert!(!is_allowed(&rule, &g, &a, &ua));
    }

    // 2 ─ Destination group mismatch  → Block
    #[test]
    fn destination_group_mismatch() {
        let mut ua = UserAction {
            to: addr(0x11), // This address is NOT in GroupA
            value: 1,
            data: Vec::new(),
            signer: [0u8; 20],
            signature: Vec::new(),
        };
        let (signer, sig, _sk) = make_sig(&ua);
        ua.signer = signer;
        ua.signature = sig;

        // policy wants dest in GroupA
        let mut groups = HashMap::<String, HashSet<[u8; 20]>>::new();
        groups.insert("GroupA".into(), HashSet::from([addr(0x10)]));

        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer,
            destination: DestinationPattern::Group("GroupA".into()),
            signer: SignerPattern::Exact(signer),
            asset: AssetPattern::Any,
        };

        let allow = HashMap::new();
        assert!(!is_allowed(&rule, &groups, &allow, &ua));
    }

    // 3 ─ Destination allow-list mismatch  → Block
    #[test]
    fn destination_allowlist_mismatch() {
        let mut ua = UserAction {
            to: addr(0x21), // This address is NOT in AllowA
            value: 1,
            data: Vec::new(),
            signer: [0u8; 20],
            signature: Vec::new(),
        };
        let (signer, sig, _sk) = make_sig(&ua);
        ua.signer = signer;
        ua.signature = sig;

        let mut allow = HashMap::<String, HashSet<[u8; 20]>>::new();
        allow.insert("AllowA".into(), HashSet::from([addr(0x20)]));

        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer,
            destination: DestinationPattern::Allowlist("AllowA".into()),
            signer: SignerPattern::Exact(signer),
            asset: AssetPattern::Any,
        };

        let groups = HashMap::new();
        assert!(!is_allowed(&rule, &groups, &allow, &ua));
    }

    // 4 ─ Signer group mismatch  → Block
    #[test]
    fn signer_group_mismatch() {
        let mut ua = UserAction {
            to: addr(0x32),
            value: 1,
            data: Vec::new(),
            signer: [0u8; 20],
            signature: Vec::new(),
        };
        let (signer_actual, sig, _sk) = make_sig(&ua);
        ua.signer = signer_actual; // The actual signer is not in GroupA
        ua.signature = sig;

        let mut groups = HashMap::<String, HashSet<[u8; 20]>>::new();
        groups.insert("GroupA".into(), HashSet::from([addr(0x30)]));

        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer,
            destination: DestinationPattern::Any,
            signer: SignerPattern::Group("GroupA".into()),
            asset: AssetPattern::Any,
        };

        let allow = HashMap::new();
        assert!(!is_allowed(&rule, &groups, &allow, &ua));
    }

    // 5 ─ Signer *Exact*, but signature **forged** → Block
    #[test]
    fn signature_invalid() {
        let mut ua = UserAction {
            to: addr(0x42),
            value: 1,
            data: Vec::new(),
            signer: [0u8; 20], // placeholder
            signature: Vec::new(),
        };

        // The policy expects a signature from `addr_true`.
        let (addr_true, _sig, _sk) = make_sig(&ua);
        ua.signer = addr_true; // Set the *claimed* signer

        // But we sign the message with a *different, fake* key.
        let sk_fake = SigningKey::random(&mut OsRng);
        let message_hash = hash_user_action(&ua);
        let Ok((signature, recovery_id)) = sk_fake.sign_prehash_recoverable(&message_hash) else {
            panic!("Failed to sign user action");
        };
        let mut fake_sig_bytes = signature.to_bytes().to_vec();
        fake_sig_bytes.push(recovery_id.to_byte());
        ua.signature = fake_sig_bytes; // Use the forged signature

        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer,
            destination: DestinationPattern::Any,
            signer: SignerPattern::Exact(addr_true),
            asset: AssetPattern::Any,
        };

        let (g, a) = empty_maps();
        // The signature recovery inside `run_policy_checks` will fail.
        assert!(!is_allowed(&rule, &g, &a, &ua));
    }

    // 6 ─ Asset exact mismatch  → Block
    #[test]
    fn asset_exact_mismatch() {
        let mut ua = UserAction {
            to: addr(0x51),
            value: 1,
            data: Vec::new(), // This implies native asset (e.g., ETH)
            signer: [0u8; 20],
            signature: Vec::new(),
        };
        let (signer, sig, _sk) = make_sig(&ua);
        ua.signer = signer;
        ua.signature = sig;

        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer,
            destination: DestinationPattern::Any,
            signer: SignerPattern::Exact(signer),
            asset: AssetPattern::Exact(addr(0xaa)), // Rule expects a specific token
        };

        let (g, a) = empty_maps();
        assert!(!is_allowed(&rule, &g, &a, &ua));
    }
}
