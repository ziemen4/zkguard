use zkguard_methods::{ZKGUARD_POLICY_ELF, ZKGUARD_POLICY_ID};
use serde::{Deserialize, Serialize};
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv};
use risc0_zkvm::serde::to_vec;
use sha3::{Digest as Sha3Digest, Keccak256};

// Environment utilities
use dotenv::dotenv;

#[derive(Clone, Debug, Serialize, Deserialize)]
struct TxWitness {
    caller:   [u8; 20],
    calldata: Vec<u8>,
    value:    u128,
    tx_hash:  [u8; 32],
    sigs:     Vec<Vec<u8>>,   // 65-byte RSV each
    deadline: u64,
}

// ---------------- helper --------------------------

fn keccak32(data: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(data);
    h.finalize().into()
}

// ---------------- demo run ------------------------

fn main() -> anyhow::Result<()> {
    dotenv().ok();

//----------------------------------------------------------
    // Build a sample calldata: transfer(allowlisted, 0.05 ETH)
    //----------------------------------------------------------
    const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    let dest: [u8; 20] = [
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, //
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, //
        0x12, 0x34, 0x56, 0x78,
    ];
    let amount: u128 = 50_000_000_000_000_000; // 0.05 ETH

    let mut calldata = Vec::from(TRANSFER_SELECTOR);
    calldata.extend([0u8; 12]);      // left-pad address
    calldata.extend(dest);
    calldata.extend(amount.to_be_bytes());

    //----------------------------------------------------------
    // Dummy signatures – just correct length for the stub
    //----------------------------------------------------------
    let dummy_sig = vec![0u8; 65];
    let sigs = vec![dummy_sig.clone(), dummy_sig]; // 2-of-3 satisfied

    //----------------------------------------------------------
    // Assemble witness & prove
    //----------------------------------------------------------
    let witness = TxWitness {
        caller: dest,
        calldata: calldata.clone(),
        value: 0,
        tx_hash: keccak32(&calldata),
        sigs,
        deadline: 1_716_000_000,
    };

    // Spin up the prover
    let env = ExecutorEnv::builder()
        .write(&to_vec(&witness)?)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();

    // Produce a receipt by proving the specified ELF binary.
    let receipt = prover.prove(env, ZKGUARD_POLICY_ELF).unwrap().receipt;

    let digest: Digest = receipt.journal.decode().unwrap();

    // Verify the receipt, ensuring the prover knows a valid keccak preimage.
    receipt
        .verify(ZKGUARD_POLICY_ID)
        .expect("receipt verification failed");

    println!("I know {:x?}", digest);
    Ok(())
}
