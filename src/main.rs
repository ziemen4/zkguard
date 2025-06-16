use anyhow::Result;
use bincode::Options;
use dotenv::dotenv;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use risc0_zkvm::{default_prover, ExecutorEnv};
use sha3::{Digest, Keccak256};
use std::collections::HashMap;
use zkguard_core::{
    ActionType, AssetPattern, DestinationPattern, Policy, PolicyLine, SignerPattern, TxType,
    UserAction,
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
    let erc20_addr: [u8; 20] = hex::decode("dAC17F958D2ee523a2206206994597C13D831ec7")? // USDT
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
        to: erc20_addr,
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
    let rule = PolicyLine {
        id: 1,
        tx_type: TxType::Transfer,
        destination: DestinationPattern::Any, // no restriction
        signer: SignerPattern::Exact(from_addr),
        asset: AssetPattern::Exact(erc20_addr),
        action: ActionType::Allow,
    };
    let policy: Policy = vec![rule];

    // Empty maps (we're not using groups / allow-lists for this rule)
    let groups: HashMap<String, Vec<[u8; 20]>> = HashMap::new();
    let allowls: HashMap<String, Vec<[u8; 20]>> = HashMap::new();

    // ---------------------------------------------------------------------
    // Encode frames (bincode + fixint)
    // ---------------------------------------------------------------------
    let user_action_bytes = encode(&user_action);
    let policy_bytes = encode(&policy);
    let group_bytes = encode(&groups);
    let allow_bytes = encode(&allowls);

    // ---------------------------------------------------------------------
    // Prove
    // ---------------------------------------------------------------------
    let env = ExecutorEnv::builder()
        .write_frame(&user_action_bytes)
        .write_frame(&policy_bytes)
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
