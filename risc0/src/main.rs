use anyhow::Result;
use bincode::Options;
use dotenv::dotenv;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use risc0_zkvm::{default_prover, ExecutorEnv};
use rs_merkle::{algorithms::Sha256 as MerkleSha256, MerkleTree};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use zkguard_core::{
    AssetPattern, DestinationPattern, MerklePath, PolicyLine, SignerPattern, TxType, UserAction,
};
use zkguard_methods::{ZKGUARD_POLICY_ELF, ZKGUARD_POLICY_ID};

// Helper to bincode-encode with fixint
fn encode<T: serde::Serialize>(data: &T) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(data)
        .unwrap()
}

// Helper to hash the UserAction exactly like the guest code
fn hash_user_action(ua: &UserAction) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(&ua.to);
    h.update(&ua.value.to_be_bytes());
    h.update(&ua.data);
    h.finalize().into()
}

// Leaf‑hash = Keccak256(bincode(PolicyLine))
fn hash_policy_line(pl: &PolicyLine) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(pl.id.to_be_bytes());
    // For TxType, DestinationPattern, SignerPattern, and AssetPattern,
    // we need to encode them to bytes for hashing.
    // Assuming they have a consistent bincode encoding.
    h.update(
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&pl.tx_type)
            .unwrap(),
    );
    h.update(
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&pl.destination)
            .unwrap(),
    );
    h.update(
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&pl.signer)
            .unwrap(),
    );
    h.update(
        bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .serialize(&pl.asset)
            .unwrap(),
    );
    // Removed pl.minimum as it's not a field in PolicyLine
    h.finalize().into()
}

/// ERC‑20 transfer(address,uint256) function selector (big‑endian).
const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

fn main() -> Result<()> {
    dotenv().ok();

    // ---------------------------------------------------------------------
    // Generate a new signer and derive its address
    // ---------------------------------------------------------------------
    let sk = SigningKey::random(&mut OsRng);
    let pk_bytes = sk.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec();
    let from_addr: [u8; 20] = Keccak256::digest(&pk_bytes)[12..].try_into()?;

    // ---------------------------------------------------------------------
    // Addresses
    // ---------------------------------------------------------------------
    let to_addr: [u8; 20] = hex::decode("12f3a2b4cC21881f203818aA1F78851Df974Bcc2")?
        .try_into()
        .unwrap();
    let usdt_addr: [u8; 20] = hex::decode("dAC17F958D2ee523a2206206994597C13D831ec7")? // USDT
        .try_into()
        .unwrap();
    let usdc_addr: [u8; 20] = hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")? // USDC
        .try_into()
        .unwrap();

    // ---------------------------------------------------------------------
    // Craft calldata for transfer(to, amount)
    // ---------------------------------------------------------------------
    let amount: u128 = 1_000_000; // 1 USDT (6 decimals → 1e6)
    let mut data = TRANSFER_SELECTOR.to_vec(); // 4-byte selector
    data.extend([0u8; 12]); // pad for `to`
    data.extend(&to_addr); // 20-byte recipient
    data.extend([0u8; 16]); // pad for uint256 hi-bits
    data.extend(&amount.to_be_bytes()); // 16-byte low bits

    // ---------------------------------------------------------------------
    // Create the UserAction and sign it
    // ---------------------------------------------------------------------
    let mut user_action = UserAction {
        to: usdt_addr,
        value: 0,
        data,
        signer: from_addr,
        signature: vec![], // Will be filled in next
    };

    // Sign the Keccak256 hash of the action
    let message_hash = hash_user_action(&user_action);
    let (signature, recovery_id) = sk.sign_prehash_recoverable(&message_hash)?;

    // Append the recovery ID to the 64-byte signature to form the 65-byte Ethereum signature
    let mut sig_bytes = signature.to_bytes().to_vec();
    sig_bytes.push(recovery_id.to_byte());
    user_action.signature = sig_bytes;

    // ---------------------------------------------------------------------
    // Build the *policy*
    // ---------------------------------------------------------------------
    let rule_0 = PolicyLine {
        id: 1,
        tx_type: TxType::Transfer,
        destination: DestinationPattern::Any, // no restriction
        signer: SignerPattern::Exact(from_addr),
        asset: AssetPattern::Exact(usdt_addr),
    };
    let rule_1 = PolicyLine {
        id: 2,
        tx_type: TxType::Transfer,
        destination: DestinationPattern::Allowlist("USDC-Allowlist".into()),
        signer: SignerPattern::Any,            // any signer
        asset: AssetPattern::Exact(usdc_addr), // only USDC
    };

    let hashed_leaves = vec![hash_policy_line(&rule_0), hash_policy_line(&rule_1)]; // Changed leaf1 to rule_1
    let tree: MerkleTree<MerkleSha256> = MerkleTree::from_leaves(&hashed_leaves);
    let root = tree.root();
    let proof = tree.proof(&[0]);
    let path_hashes: Vec<[u8; 32]> = proof.proof_hashes().to_vec();

    let merkle_path = MerklePath {
        leaf_index: 0u64,              // Changed `index` to `leaf_index`
        siblings: path_hashes.clone(), // Changed `path` to `siblings`
    };
    let merkle_root: [u8; 32] = root.expect("Merkle tree should have a root");
    let merkle_root_vec: Vec<u8> = merkle_root.to_vec();
    // Empty maps (we're not using groups / allow-lists for this rule)
    let groups: HashMap<String, Vec<[u8; 20]>> = HashMap::new();
    let allows: HashMap<String, Vec<[u8; 20]>> = HashMap::new();

    // ---------------------------------------------------------------------
    // Encode frames (bincode + fixint)
    // ---------------------------------------------------------------------
    let root_bytes = encode(&merkle_root_vec);
    let user_action_bytes = encode(&user_action);
    let leaf_bytes = encode(&rule_0);
    let path_bytes = encode(&merkle_path);
    let group_bytes = encode(&groups);
    let allow_bytes = encode(&allows);

    println!("[ZKGuard] Writing frames to the prover environment...");
    println!(
        "[ZKGuard] Policy Merkle root length in bytes: {:?}",
        root_bytes.len()
    );
    println!(
        "[ZKGuard] User action length in bytes: {:?}",
        user_action_bytes.len()
    );
    println!(
        "[ZKGuard] Policy line length in bytes: {:?}",
        leaf_bytes.len()
    );
    println!(
        "[ZKGuard] Merkle path length in bytes: {:?}",
        path_bytes.len()
    );
    println!("[ZKGuard] Groups length in bytes: {:?}", group_bytes.len());
    println!(
        "[ZKGuard] Allow-lists length in bytes: {:?}",
        allow_bytes.len()
    );

    // ---------------------------------------------------------------------
    // Prove
    // ---------------------------------------------------------------------
    let env = ExecutorEnv::builder()
        .write_frame(&root_bytes)
        .write_frame(&user_action_bytes)
        .write_frame(&leaf_bytes)
        .write_frame(&path_bytes)
        .write_frame(&group_bytes)
        .write_frame(&allow_bytes)
        .build()?;

    println!("Proving...");
    let prover = default_prover();
    let receipt = prover.prove(env, ZKGUARD_POLICY_ELF)?.receipt;
    println!("Proved!");

    // ---------------------------------------------------------------------
    // Verify
    // ---------------------------------------------------------------------
    println!("Verifying...");
    receipt.verify(ZKGUARD_POLICY_ID)?;
    println!("Verified!");

    // The guest commits four 32-byte hashes; here we just dump them:
    println!("Decoding committed hashes... ");
    let hashes: Vec<[u8; 32]> = receipt.journal.decode()?;
    assert_eq!(hashes.len(), 4);

    println!("Committed hashes (call, policy, groups, allow):");
    for (i, h) in hashes.iter().enumerate() {
        println!("  {}: 0x{}", i, hex::encode(h));
    }

    println!("Decoded committed hashes.\n");
    Ok(())
}
