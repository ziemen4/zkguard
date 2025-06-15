extern crate alloc;
use alloc::vec::Vec;

use bincode::Options;
use risc0_zkvm::guest::{entry, env};
use std::collections::{BTreeMap, HashMap, HashSet};
use zkguard_core::{keccak256, Policy, UserAction};

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

// TODO: benchmark whether *rejecting* non-canonical inputs and failing the
//       proof is cheaper than the in-circuit canonicalisation we do here.
fn canonicalise_policy(mut raw: Policy) -> (Policy, Vec<u8>) {
    raw.sort_by_key(|l| l.id);
    // Detect duplicate IDs (optional, but guards against ambiguity):
    for win in raw.windows(2) {
        if win[0].id == win[1].id {
            panic!("duplicate policy id");
        }
    }
    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&raw)
        .expect("serialise canonical policy");
    (raw, bytes)
}

// ================================================================
// Implements a line‑by‑line policy evaluator for wallet actions and
// exposes a `main` that the ZKP wrapper invokes.  Frames sent by the
// host arrive in the following order:
//   1. UserAction   (bincode, fixint)
//   2. Policy       (Vec<PolicyLine>)
//   3. Groups       (HashMap<String, Vec<[u8;20]>>)
//   4. Allow‑lists  (HashMap<String, Vec<[u8;20]>>)
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
    // 1. read the frame sent by the host ------------------------
    let bytes: Vec<u8> = env::read_frame();

    // 2. deserialize it (bincode, fixint) -----------------------
    let user_action: UserAction = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&bytes)
        .expect("deserialize ProofInput");

    // 3. policy ------------------------------------------------------------
    let policy_raw_bytes: Vec<u8> = env::read_frame();
    let raw_policy: Policy = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&policy_raw_bytes)
        .expect("deserialize Policy");
    let (policy, policy_bytes) = canonicalise_policy(raw_policy);

    // 4. groups ------------------------------------------------------------
    let groups_raw_bytes: Vec<u8> = env::read_frame();
    let raw_groups: HashMap<String, Vec<[u8; 20]>> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&groups_raw_bytes)
        .expect("deserialize Groups");
    let (groups_canon, groups_bytes) = canonicalise_lists(raw_groups);
    let groups_sets: HashMap<String, HashSet<[u8; 20]>> = groups_canon
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
        .collect();

    // 5. allow‑lists -------------------------------------------------------
    let allow_raw_bytes: Vec<u8> = env::read_frame();
    let raw_allow: HashMap<String, Vec<[u8; 20]>> = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&allow_raw_bytes)
        .expect("deserialize Allow-lists");
    let (allow_canon, allow_bytes) = canonicalise_lists(raw_allow);
    let allow_sets: HashMap<String, HashSet<[u8; 20]>> = allow_canon
        .iter()
        .map(|(k, v)| (k.clone(), v.iter().copied().collect()))
        .collect();

    // 6. evaluate policy ----------------------------------------
    let allowed = run_policy_checks(&policy, &groups_sets, &allow_sets, &user_action);
    assert!(allowed, "policy-violation");

    // 7. commitments
    let call_hash = keccak256(&user_action.data);
    let policy_hash = keccak256(&policy_bytes);
    let groups_hash = keccak256(&groups_bytes);
    let allow_hash = keccak256(&allow_bytes);

    let hashes = vec![call_hash, policy_hash, groups_hash, allow_hash];
    env::commit(&hashes);
}
