use anyhow::Result;
use bincode::Options;
use dotenv::dotenv;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use risc0_zkvm::{default_prover, ExecutorEnv};
use rs_merkle::MerkleTree;
use std::collections::HashMap;
// CHANGE: Import the `Hasher` trait from tiny_keccak
use tiny_keccak::{Hasher, Keccak};
use zkguard_core::{
    hash_policy_line_for_merkle_tree, AssetPattern, DestinationPattern, MerklePath,
    PolicyLine, Sha256MerkleHasher, SignerPattern, TxType, UserAction,
};
use zkguard_methods::{ZKGUARD_POLICY_ELF, ZKGUARD_POLICY_ID};

// Helper to bincode-encode with fixint
fn encode<T: serde::Serialize>(data: &T) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(data)
        .unwrap()
}

// CHANGE: Updated to use the correct tiny-keccak API
fn hash_user_action(ua: &UserAction) -> [u8; 32] {
    // 1. Create a Keccak-256 hasher instance
    let mut h = Keccak::v256();
    // 2. Create an output buffer for the hash
    let mut output = [0u8; 32];

    // 3. Update the hasher with data
    h.update(&ua.to);
    h.update(&ua.value.to_be_bytes());
    h.update(&ua.data);

    // 4. Finalize into the buffer
    h.finalize(&mut output);

    // 5. Return the result
    output
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

    // CHANGE: Manually hash to derive address, since `Keccak::digest` doesn't exist
    let mut hasher = Keccak::v256();
    let mut pk_hash = [0u8; 32];
    hasher.update(&pk_bytes);
    hasher.finalize(&mut pk_hash);
    let from_addr: [u8; 20] = pk_hash[12..].try_into()?;

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
        signatures: vec![], // Will be filled in next
    };

    // Sign the Keccak256 hash of the action
    let message_hash = hash_user_action(&user_action);
    let (signature, recovery_id) = sk.sign_prehash_recoverable(&message_hash)?;

    // Append the recovery ID to the 64-byte signature to form the 65-byte Ethereum signature
    let mut sig_bytes = signature.to_bytes().to_vec();
    sig_bytes.push(recovery_id.to_byte());
    user_action.signatures = vec![sig_bytes];

    // ---------------------------------------------------------------------
    // Build the *policy*
    // ---------------------------------------------------------------------
    let rule_0 = PolicyLine {
        id: 1,
        tx_type: TxType::Transfer,
        destination: DestinationPattern::Any, // no restriction
        signer: SignerPattern::Threshold {
            group: "Admins".to_string(),
            threshold: 1,
        },
        asset: AssetPattern::Exact(usdt_addr),
        amount_max: Some(amount), // max 1 USDT
        function_selector: None,
    };
    let rule_1 = PolicyLine {
        id: 2,
        tx_type: TxType::Transfer,
        destination: DestinationPattern::Allowlist("USDC-Allowlist".into()),
        signer: SignerPattern::Any,            // any signer
        asset: AssetPattern::Exact(usdc_addr), // only USDC
        amount_max: None, // no limit
        function_selector: None,
    };

    let rule_2 = PolicyLine {
        id: 3,
        tx_type: TxType::ContractCall,
        destination: DestinationPattern::Any,
        signer: SignerPattern::Exact(from_addr),
        asset: AssetPattern::Any,
        amount_max: None,
        function_selector: Some([0x7f, 0xf3, 0x6a, 0xb5]), // swapExactETHForTokens
    };

    let hashed_leaves = vec![
        hash_policy_line_for_merkle_tree(&rule_0),
        hash_policy_line_for_merkle_tree(&rule_1),
        hash_policy_line_for_merkle_tree(&rule_2),
    ];
    let tree: MerkleTree<Sha256MerkleHasher> = MerkleTree::from_leaves(&hashed_leaves);
    let root = tree.root();
    let proof = tree.proof(&[0]);
    let path_hashes: Vec<[u8; 32]> = proof.proof_hashes().to_vec();

    let merkle_path = MerklePath {
        leaf_index: 0u64,              // Changed `index` to `leaf_index`
        siblings: path_hashes.clone(), // Changed `path` to `siblings`
    };
    let merkle_root: [u8; 32] = root.expect("Merkle tree should have a root");
    let mut groups: HashMap<String, Vec<[u8; 20]>> = HashMap::new();
    groups.insert("Admins".to_string(), vec![from_addr]);
    let allows: HashMap<String, Vec<[u8; 20]>> = HashMap::new();

    // ---------------------------------------------------------------------
    // Encode frames (bincode + fixint)
    // ---------------------------------------------------------------------
    let root_bytes = encode(&merkle_root.to_vec());
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