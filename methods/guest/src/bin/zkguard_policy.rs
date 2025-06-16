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

    println!("[ZKGuard] Call hash: {:?}", call_hash);
    println!("[ZKGuard] Policy hash: {:?}", policy_hash);
    println!("[ZKGuard] Groups hash: {:?}", groups_hash);
    println!("[ZKGuard] Allow-list hash: {:?}", allow_hash);
    let hashes: Vec<[u8; 32]> = vec![call_hash, policy_hash, groups_hash, allow_hash];
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
        ActionType, AssetPattern, DestinationPattern, Policy, PolicyLine, SignerPattern, TxType,
        UserAction,
    };

    /*─────────────────  helpers  ─────────────────*/

    // Helper to hash the UserAction exactly like the guest code
    fn hash_user_action(ua: &UserAction) -> [u8; 32] {
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

    /// Wrap the engine, treating *panic* as a “block”
    fn is_allowed(
        p: &Policy,
        g: &HashMap<String, HashSet<[u8; 20]>>,
        a: &HashMap<String, HashSet<[u8; 20]>>,
        ua: &UserAction,
    ) -> bool {
        std::panic::catch_unwind(|| run_policy_checks(p, g, a, ua)).unwrap_or(false)
    }

    /// Tiny address helper
    fn addr(b: u8) -> [u8; 20] {
        [b; 20]
    }

    /*─────────────────  tests  ─────────────────*/

    // 1 ─ Transfer rule but action is ContractCall  → Block
    #[test]
    fn transfer_rule_vs_contract_call() {
        let mut ua = UserAction {
            to: addr(0x02),
            value: 0,
            data: vec![0xaa], // contract call
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
            asset: AssetPattern::Any,
            action: ActionType::Allow,
        };

        let (g, a) = empty_maps();
        assert!(!is_allowed(&vec![rule], &g, &a, &ua));
    }

    // 2 ─ Destination group mismatch  → Block
    #[test]
    fn destination_group_mismatch() {
        // signer + sig first
        let mut ua = UserAction {
            to: addr(0x11),
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
            action: ActionType::Allow,
        };

        let allow = HashMap::new();
        assert!(!is_allowed(&vec![rule], &groups, &allow, &ua));
    }

    // 3 ─ Destination allow-list mismatch  → Block
    #[test]
    fn destination_allowlist_mismatch() {
        let mut ua = UserAction {
            to: addr(0x21),
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
            action: ActionType::Allow,
        };

        let groups = HashMap::new();
        assert!(!is_allowed(&vec![rule], &groups, &allow, &ua));
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
        let (sign_good, sig, _sk) = make_sig(&ua); // produce *valid* signer
        ua.signer = sign_good;
        ua.signature = sig;

        let mut groups = HashMap::<String, HashSet<[u8; 20]>>::new();
        groups.insert("GroupA".into(), HashSet::from([addr(0x30)]));

        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer,
            destination: DestinationPattern::Any,
            signer: SignerPattern::Group("GroupA".into()),
            asset: AssetPattern::Any,
            action: ActionType::Allow,
        };

        let allow = HashMap::new();
        assert!(!is_allowed(&vec![rule], &groups, &allow, &ua));
    }

    // 5 ─ Signer *Exact*, but signature **forged**  → Block
    #[test]
    fn signature_invalid() {
        // Step 1: build the action (we'll sign it with a *different* key)
        let mut ua = UserAction {
            to: addr(0x42),
            value: 1,
            data: Vec::new(),
            signer: [0u8; 20], // placeholder
            signature: Vec::new(),
        };

        // Step 2: get actual signer and signature
        let (addr_true, _sig, _sk) = make_sig(&ua);
        ua.signer = addr_true;

        // Step 3: generate a different signature and update the ua with it
        let sk = SigningKey::random(&mut OsRng);
        let message_hash = hash_user_action(&ua);
        let Ok((signature, recovery_id)) = sk.sign_prehash_recoverable(&message_hash) else {
            panic!("Failed to sign user action");
        };
        let mut fake_sig_bytes = signature.to_bytes().to_vec();
        fake_sig_bytes.push(recovery_id.to_byte());
        ua.signature = fake_sig_bytes;

        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer,
            destination: DestinationPattern::Any,
            signer: SignerPattern::Exact(addr_true),
            asset: AssetPattern::Any,
            action: ActionType::Allow,
        };

        let (g, a) = empty_maps();
        assert!(!is_allowed(&vec![rule], &g, &a, &ua));
    }

    // 6 ─ Asset exact mismatch  → Block
    #[test]
    fn asset_exact_mismatch() {
        let mut ua = UserAction {
            to: addr(0x51),
            value: 1,
            data: Vec::new(),
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
            asset: AssetPattern::Exact(addr(0xaa)), // expects USDT
            action: ActionType::Allow,
        };

        let (g, a) = empty_maps();
        assert!(!is_allowed(&vec![rule], &g, &a, &ua));
    }

    // 7 ─ Tx-type mismatch (ContractCall vs Transfer)  → Block
    #[test]
    fn tx_type_mismatch_any_asset() {
        let mut ua = UserAction {
            to: addr(0x61),
            value: 0,
            data: vec![0xbe],
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
            signer: SignerPattern::Any,
            asset: AssetPattern::Any,
            action: ActionType::Allow,
        };

        let (g, a) = empty_maps();
        assert!(!is_allowed(&vec![rule], &g, &a, &ua));
    }

    // 8 ─ Explicit Block rule  → Block
    #[test]
    fn explicit_block_rule() {
        let mut ua = UserAction {
            to: addr(0x71),
            value: 1,
            data: Vec::new(),
            signer: [0u8; 20],
            signature: Vec::new(),
        };
        let (signer, sig, _sk) = make_sig(&ua);
        ua.signer = signer;
        ua.signature = sig;

        let mut allow = HashMap::<String, HashSet<[u8; 20]>>::new();
        allow.insert("BlockB".into(), HashSet::from([addr(0x71)]));

        let rule = PolicyLine {
            id: 1,
            tx_type: TxType::Transfer,
            destination: DestinationPattern::Allowlist("BlockB".into()),
            signer: SignerPattern::Any,
            asset: AssetPattern::Any,
            action: ActionType::Block,
        };

        let groups = HashMap::new();
        assert!(!is_allowed(&vec![rule], &groups, &allow, &ua));
    }

    // 9 ─ Empty policy  → Block
    #[test]
    fn empty_policy_blocks() {
        let mut ua = UserAction {
            to: addr(0x81),
            value: 1,
            data: Vec::new(),
            signer: [0u8; 20],
            signature: Vec::new(),
        };
        let (signer, sig, _sk) = make_sig(&ua);
        ua.signer = signer;
        ua.signature = sig;

        let (g, a) = empty_maps();
        assert!(!is_allowed(&Vec::new(), &g, &a, &ua));
    }
}
