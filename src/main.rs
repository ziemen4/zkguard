use dotenv::dotenv;
use risc0_zkvm::{default_prover, Digest, ExecutorEnv};
use zkguard_methods::{ZKGUARD_POLICY_ELF, ZKGUARD_POLICY_ID};
use zkguard_core::{
    constants::TRANSFER_SELECTOR,
    AuthRequest,
};
use bincode::Options;

// --------------- demo run ---------------------
fn main() -> anyhow::Result<()> {
    dotenv().ok();

    // Some from address
    let from_str = "0xa6321351cC21881f203818aA1F78851Df974Bcc2";
    let from = hex::decode(from_str.strip_prefix("0x").unwrap()).unwrap();

    // Some to address (where we want to send the ERC20)
    let to_str = "0x12f3a2b4cC21881f203818aA1F78851Df974Bcc2";
    let to = hex::decode(to_str.strip_prefix("0x").unwrap()).unwrap();

    // Define the amount 
    let amount= 1_000_000u128; // 1e6 tokens

    // Define the ERC20 contract address
    let erc20_str = "0xdAC17F958D2ee523a2206206994597C13D831ec7";
    let erc20: Vec<u8> = hex::decode(erc20_str.strip_prefix("0x").unwrap()).unwrap();

    // Create calldata for a transfer of 1 (1e6) ERC20 token to "to"
    // transfer(address,uint256)

    // Encode to 4 bytes for the selector (frist 4 bytes of keccak256("transfer(address,uint256)"))
    let mut data = TRANSFER_SELECTOR.to_vec();
    // Encode to 32 bytes, pad with 12 zeros and then 20 bytes of "to"
    data.extend([0u8; 12]);           // pad for `to` offset
    data.extend(to);                  // recipient

    // Encode to 32 bytes, pad with 16 zeros and then 16 bytes of amount (since in Rust we have u128)
    data.extend([0u8; 16]);           // pad for `amount` offset
    data.extend(&amount.to_be_bytes()); // amount
    println!("Amount bytes: {:?}", &data[36..]);
    

    let tx_req = AuthRequest::Transaction {
        from: from.try_into().unwrap(),
        to: erc20.try_into().unwrap(),
        value: 0,
        data
    };

    let bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(&tx_req)?;

    let env = ExecutorEnv::builder()
        .write_frame(&bytes)
        .build()?;

    println!("Proving...");
    let prover  = default_prover();
    let receipt  = prover.prove(env, ZKGUARD_POLICY_ELF)?.receipt;
    println!("Proved!");

    // --- verify the receipt -------------------
    println!("Verifying...");
    let digest: Digest = receipt.journal.decode()?;
    receipt.verify(ZKGUARD_POLICY_ID)
           .expect("receipt verification failed");
    println!("Verified!");

    println!("I know {:x?}", digest);
    Ok(())
}
