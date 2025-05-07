#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::{entry, env};
use bincode::Options;
use zkguard_core::{
    constants::{HIGH_VALUE, MAX_PER_TX},
    parse_action,
    Action,
    AuthRequest,
};

////////////////////////////////////////////////////////////////
//  Entry ‑‑ policy evaluation
////////////////////////////////////////////////////////////////
entry!(main);

fn main() {
    // 1) read raw bytes that the host wrote
    println!("Reading frame...");
    let bytes: Vec<u8> = env::read_frame();
    println!("Read {} bytes", bytes.len());

    // 2) deserialize with the same codec the host used
    println!("Deserializing...");
    let auth_request: AuthRequest = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .deserialize(&bytes)
        .unwrap();
    println!("Deserialized {:?}", auth_request);
    
    // 3) extract raw calldata & sigs for policy checks
    println!("Extracting calldata & sigs...");
    let (calldata, sigs): (Vec<u8>, Vec<Vec<u8>>) = match auth_request {
        AuthRequest::Transaction { data, sigs, .. }       => (data, sigs),
        AuthRequest::UserOperation { call_data, signature, .. } => (call_data, vec![signature]),
    };
    println!("Extracted {} bytes of calldata and {} signatures", calldata.len(), sigs.len());

    // 4) decode calldata
    println!("Decoding calldata...");
    let action = match parse_action(&calldata) {
        Some(a) => a,
        None    => { env::commit(&false); return; }
    };
    println!("Decoded action: {:?}", action);

    // 5) apply policy
    println!("Applying policy...");
    let allowed = match action {
        Action::Transfer { amount, .. } => {
            if amount > MAX_PER_TX {
                false
            } else if amount > HIGH_VALUE {
                // zkguard_core::check_multisig(&tx_hash, &sigs) – stub for future
                true
            } else {
                true
            }
        }
        Action::ContractCall { .. } => {
            // zkguard_core::check_multisig(&tx_hash, &sigs)
            true
        }
    };
    println!("Policy result: {}", allowed);

    // 6) commit result to the journal
    println!("Committing...");
    env::commit(&allowed);
    println!("Done.");
}
