extern crate alloc;
use alloc::vec::Vec;

use bincode::Options;
use risc0_zkvm::guest::{entry, env};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap, HashSet};

use zkguard_core::{MerklePath, PolicyLine, UserAction};
use zkguard_guest::policy_engine::run_policy_checks;

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
fn verify_merkle_proof(root: &[u8], leaf_bytes: &[u8], proof: &MerklePath) -> bool {
    env::log(&format!("verify_merkle_proof: Expected root: {:?}", root));
    env::log(&format!(
        "verify_merkle_proof: Leaf bytes length: {}",
        leaf_bytes.len()
    ));
    env::log(&format!(
        "verify_merkle_proof: Leaf index: {}",
        proof.leaf_index
    ));
    env::log(&format!(
        "verify_merkle_proof: Number of siblings: {}",
        proof.siblings.len()
    ));

    // CHANGE: Use the cleaner one-shot digest from the `sha2` crate.
    let mut computed_hash: [u8; 32] = Sha256::digest(leaf_bytes).into();

    env::log(&format!(
        "verify_merkle_proof: Initial computed hash: {:?}",
        computed_hash
    ));

    let mut current_index = proof.leaf_index;

    for (i, sibling_hash) in proof.siblings.iter().enumerate() {
        env::log(&format!(
            "verify_merkle_proof: Step {}, current_index: {}, sibling: {:?}",
            i, current_index, sibling_hash
        ));

        let mut combined = Vec::with_capacity(64);
        if current_index % 2 == 0 {
            combined.extend_from_slice(&computed_hash);
            combined.extend_from_slice(sibling_hash);
            env::log("verify_merkle_proof: Left child + Right sibling");
        } else {
            combined.extend_from_slice(sibling_hash);
            combined.extend_from_slice(&computed_hash);
            env::log("verify_merkle_proof: Left sibling + Right child");
        }

        // CHANGE: Use the one-shot digest again for subsequent hashes.
        computed_hash = Sha256::digest(&combined).into();

        env::log(&format!(
            "verify_merkle_proof: Computed hash after step {}: {:?}",
            i, computed_hash
        ));

        current_index /= 2; // Move up to the parent level
    }

    let result = computed_hash.as_slice() == root;
    env::log(&format!(
        "verify_merkle_proof: Final computed hash: {:?}",
        computed_hash
    ));
    env::log(&format!(
        "verify_merkle_proof: Merkle proof result: {}",
        result
    ));
    result
}

entry!(main);

fn main() {
    // ──────────────────────────────────────────────────────────────────────
    // Read all inputs from the host
    // ──────────────────────────────────────────────────────────────────────
    env::log("[ZKGuard] Reading inputs from the prover environment...");
    let bytes_policy_merkle_root: Vec<u8> = env::read_frame();
    let policy_merkle_root: Vec<u8> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&bytes_policy_merkle_root)
        .expect("deserialize Merkle root");

    let bytes_user_action: Vec<u8> = env::read_frame();
    let user_action: UserAction = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&bytes_user_action)
        .expect("deserialize UserAction");

    let bytes_policy_line: Vec<u8> = env::read_frame();
    let policy_line: PolicyLine = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&bytes_policy_line)
        .expect("deserialize PolicyLine");

    let bytes_policy_merkle_path: Vec<u8> = env::read_frame();
    let policy_merkle_path = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize::<MerklePath>(&bytes_policy_merkle_path)
        .expect("deserialize MerklePath");

    let bytes_raw_groups: Vec<u8> = env::read_frame();
    let raw_groups: HashMap<String, Vec<[u8; 20]>> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&bytes_raw_groups)
        .expect("deserialize Groups");
    let (groups_canon, groups_bytes) = canonicalise_lists(raw_groups);
    let groups_sets: HashMap<String, HashSet<[u8; 20]>> = groups_canon
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
        .collect();

    let bytes_raw_allowed: Vec<u8> = env::read_frame();
    let raw_allowed: HashMap<String, Vec<[u8; 20]>> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&bytes_raw_allowed)
        .expect("deserialize Allow-lists");
    let (allow_canon, allow_bytes) = canonicalise_lists(raw_allowed);
    let allow_sets: HashMap<String, HashSet<[u8; 20]>> = allow_canon
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
        .collect();

    env::log("[ZKGuard] Finished reading inputs.");

    // ──────────────────────────────────────────────────────────────────────
    // Run all verification logic
    // ──────────────────────────────────────────────────────────────────────
    let proof_is_valid =
        verify_merkle_proof(&policy_merkle_root, &bytes_policy_line, &policy_merkle_path);
    assert!(proof_is_valid, "merkle-proof-invalid");

    let allowed = run_policy_checks(&policy_line, &groups_sets, &allow_sets, &user_action);
    assert!(allowed, "policy-violation");

    // ──────────────────────────────────────────────────────────────────────
    // Commit the hashes of the inputs used for verification
    // ──────────────────────────────────────────────────────────────────────
    // CHANGE: Use the cleaner `sha2` crate API for all hashes.
    let call_hash: [u8; 32] = Sha256::digest(&user_action.data).into();

    let root: [u8; 32] = policy_merkle_root
        .try_into()
        .expect("expected 32 bytes for Merkle root");

    let groups_hash: [u8; 32] = Sha256::digest(&groups_bytes).into();

    let allow_hash: [u8; 32] = Sha256::digest(&allow_bytes).into();

    env::log(&format!("[ZKGuard] Call hash: {:?}", call_hash));
    env::log(&format!("[ZKGuard] Policy Merkle root: {:?}", root));
    env::log(&format!("[ZKGuard] Groups hash: {:?}", groups_hash));
    env::log(&format!("[ZKGuard] Allow-list hash: {:?}", allow_hash));

    let hashes: Vec<[u8; 32]> = vec![call_hash, root, groups_hash, allow_hash];
    env::log(&format!("[ZKGuard] Committing hashes: {:?}", hashes));
    env::commit(&hashes);
}