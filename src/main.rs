use dotenv::dotenv;
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv};
use zkguard_methods::{ZKGUARD_POLICY_ELF, ZKGUARD_POLICY_ID};
use zkguard_core::{
    constants::TRANSFER_SELECTOR,
    AuthRequest,
};
use bincode::Options;

// --------------- demo run ---------------------
fn main() -> anyhow::Result<()> {
    dotenv().ok();

    // --- craft a Transaction variant -----------
    let to = [0x12; 20];
    let mut data = TRANSFER_SELECTOR.to_vec();
    data.extend([0u8; 12]);           // pad for `to` offset
    data.extend(to);                  // recipient
    data.extend(50_000_000_000_000_000u128.to_be_bytes());

    let tx_req = AuthRequest::Transaction {
        from: to,
        to,
        value: 0,
        data,
        sigs: vec![vec![0u8; 65], vec![0u8; 65]], // dummy 2‑of‑3
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
    let digest: bool = receipt.journal.decode()?;
    receipt.verify(ZKGUARD_POLICY_ID)
           .expect("receipt verification failed");
    println!("Verified!");

    println!("I know {:x?}", digest);
    Ok(())
}
