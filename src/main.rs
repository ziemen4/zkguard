use zkguard_methods::{ZKGUARD_POLICY_ELF, ZKGUARD_POLICY_ID};
use serde::{Deserialize, Serialize};
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv};
use risc0_zkvm::serde::to_vec;
use sha3::{Digest as Sha3Digest, Keccak256};

// Environment utilities
use dotenv::dotenv;

/// A unified “request” type: either an EOA tx or an ERC-4337 op.
/// We use internally-typed numeric fields for simplicity;
/// JSON/ABI hex parsing happens at the edges.
///
/// The `#[serde(tag="kind")]` form ensures the first byte
/// tells us which variant we’re deserializing.
#[derive(Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum AuthRequest {
    Transaction {
        /// EOA “from”
        from: [u8;20],
        /// target contract or 0x00… for creations
        to:   [u8;20],
        /// msg.value
        value: u128,
        /// raw calldata (abi‐encoded selector + args)
        data:  Vec<u8>,
        /// signatures over the entire RLP‐encoded tx blob
        sigs:  Vec<Vec<u8>>,
    },
    UserOperation {
        sender:                    [u8;20],
        nonce:                     u128,
        factory:                   [u8;20],
        factory_data:              Vec<u8>,
        call_data:                 Vec<u8>,
        call_gas_limit:            u128,
        verification_gas_limit:    u128,
        pre_verification_gas:      u128,
        max_fee_per_gas:           u128,
        max_priority_fee_per_gas:  u128,
        paymaster:                 [u8;20],
        paymaster_verification_gas_limit: u128,
        paymaster_post_op_gas_limit:      u128,
        paymaster_data:            Vec<u8>,
        signature:                 Vec<u8>,
    },
}


// ---------------- demo run ------------------------

fn main() -> anyhow::Result<()> {
    dotenv().ok();

    // --- demo: build a simple Transaction variant ------------
    let transfer_selector = [0xa9,0x05,0x9c,0xbb];
    let to = [0x12;20];
    let mut data = transfer_selector.to_vec();
    data.extend([0u8;12]);
    data.extend(to);
    data.extend(50_000_000_000_000_000u128.to_be_bytes());

    let tx_req = AuthRequest::Transaction {
        from: to,
        to,
        value: 0,
        data,
        sigs: vec![vec![0u8;65], vec![0u8;65]], // dummy 2-of-3
    };

    // --- serialize and prove ----------------
    let env = ExecutorEnv::builder()
        .write(&to_vec(&tx_req)?)
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
