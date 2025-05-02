use zkguard_methods::{ZKGUARD_POLICY_ELF, ZKGUARD_POLICY_ID};
use serde::{Deserialize, Serialize};
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv};
use risc0_zkvm::serde::to_vec;

// Environment utilities
use dotenv::dotenv;

/// The data structure the guest expects.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Input {
    to:    [u8; 20],   // EOA or contract address (20 bytes)
    value: u128,       // amount in wei
}

fn main() -> anyhow::Result<()> {
    dotenv().ok();

    // example that *passes* the hard-coded policy in the guest
    let inp = Input {
        to: [
            0x12, 0x34, 0x56, 0x78, 0x90,
            0xab, 0xcd, 0xef, 0x12, 0x34,
            0x56, 0x78, 0x90, 0xab, 0xcd,
            0xef, 0x12, 0x34, 0x56, 0x78,
        ],
        value: 50_000_000_000_000_000, // 0.05 ETH
    };

    // Spin up the prover
    let env = ExecutorEnv::builder()
        .write(&to_vec(&inp)?)
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
