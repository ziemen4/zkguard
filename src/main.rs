use anyhow::Result;
use bincode::Options;
use dotenv::dotenv;
use risc0_zkvm::{default_prover, Digest, ExecutorEnv};
use std::collections::HashMap;
use zkguard_core::{
    constants::TRANSFER_SELECTOR, ActionType, AssetPattern, DestinationPattern, Policy, PolicyLine,
    SignerPattern, TxType, UserAction,
};
use zkguard_methods::{ZKGUARD_POLICY_ELF, ZKGUARD_POLICY_ID};

fn encode<T: serde::Serialize>(v: &T) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(v)
        .unwrap()
}

fn main() -> Result<()> {
    dotenv().ok();

    // ---------------------------------------------------------------------
    // Addresses ------------------------------------------------------------
    // ---------------------------------------------------------------------
    let from = hex::decode("a6321351cC21881f203818aA1F78851Df974Bcc2")?;
    let to = hex::decode("12f3a2b4cC21881f203818aA1F78851Df974Bcc2")?;
    let erc20 = hex::decode("dAC17F958D2ee523a2206206994597C13D831ec7")?; // USDT

    // ---------------------------------------------------------------------
    // Craft calldata for `transfer(to, amount)` ---------------------------
    // ---------------------------------------------------------------------
    let amount: u128 = 1_000_000; // 1 USDT (6 decimals → 1e6)
    let mut data = TRANSFER_SELECTOR.to_vec(); // 4-byte selector
    data.extend([0u8; 12]); // pad for `to`
    data.extend(&to); // 20-byte recipient
    data.extend([0u8; 16]); // pad for uint256 hi-bits
    data.extend(&amount.to_be_bytes()); // 16-byte low bits

    let user_action = UserAction {
        to: erc20.clone().try_into().unwrap(),
        value: 0,
        data,
        signer: from.clone().try_into().unwrap(),
    };

    // ---------------------------------------------------------------------
    // Build the *policy* ---------------------------------------------------
    // ---------------------------------------------------------------------
    let rule = PolicyLine {
        id: 1,
        tx_type: TxType::Transfer,
        destination: DestinationPattern::Any, // no restriction
        signer: SignerPattern::Exact(from.clone().try_into().unwrap()),
        asset: AssetPattern::Exact(erc20.clone().try_into().unwrap()),
        action: ActionType::Allow,
    };
    let policy: Policy = vec![rule];

    // Empty maps (we're not using groups / allow-lists for this rule)
    let groups: HashMap<String, Vec<[u8; 20]>> = HashMap::new();
    let allowls: HashMap<String, Vec<[u8; 20]>> = HashMap::new();

    // ---------------------------------------------------------------------
    // Encode frames (bincode + fixint) ----------------------------------
    // ---------------------------------------------------------------------
    let user_action_bytes = encode(&user_action);
    let policy_bytes = encode(&policy);
    let group_bytes = encode(&groups);
    let allow_bytes = encode(&allowls);

    // ---------------------------------------------------------------------
    // Prove ----------------------------------------------------------------
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
    // Verify ---------------------------------------------------------------
    // ---------------------------------------------------------------------
    println!("Verifying...");
    receipt.verify(ZKGUARD_POLICY_ID)?;
    println!("Verified!");

    // The guest commits four 32-byte hashes; here we just dump them:
    println!("Decoding committed hashes... ");
    let hashes: Vec<Digest> = receipt.journal.decode()?;
    println!("Decoded committed hashes.\n");
    println!("Committed hashes (call, policy, groups, allow):");
    for (i, h) in hashes.iter().enumerate() {
        println!("  {}: {:x?}", i, h);
    }

    Ok(())
}
