#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use risc0_zkvm::guest::{entry, env};
use bincode::Options;
use zkguard_core::{
    parse_action,
    Action,
    AuthRequest,
    keccak256,
};
use std::collections::HashMap;
use once_cell::sync::Lazy;
use hex_literal::hex;

/// USDT contract address in Ethereum mainnet
pub const USDT_CONTRACT: [u8; 20] = hex!("dAC17F958D2ee523a2206206994597C13D831ec7");
/// MAX_PER_TX_MAP for defined ERC20 tokens
pub static MAX_PER_TX_MAP: Lazy<HashMap<[u8; 20], u128>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert(USDT_CONTRACT, 100_000_000); // 100 USDT
    m
});

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

    // 3) run policy checks
    println!("Running policy checks...");
    let target = if let Some(target) = auth_request.target() {
        target
    } else {
        println!("No target address found");
        panic!("No target address found");
    };

    let allowed = run_policy_checks(
        target,
        &auth_request,
    );
    assert!(allowed, "policy-violation");
    println!("Policy checks passed!");

    // 4) commit the result to the journal
    println!("Committing...");
    let mut bytes = Vec::new();
    if let Some(data) = auth_request.data() {
        bytes.extend(data);
    }
    let commit = keccak256(&bytes);
    println!("Commit: {:?}", hex::encode(commit));
    env::commit(&commit);
    println!("Commit done!");
}

fn run_policy_checks(target: &[u8; 20], auth_request: &AuthRequest) -> bool {
    // 1) extract raw calldata for policy checks
    println!("Extracting calldata...");
    let calldata: Vec<u8> = match auth_request {
        AuthRequest::Transaction { data, .. } => data.clone(),
        AuthRequest::UserOperation { call_data, .. } => call_data.clone(),
    };
    println!("Extracted {} bytes of calldata", calldata.len());

    // 2) decode calldata
    println!("Decoding calldata...");
    let action = match parse_action(target, &calldata) {
        Some(a) => a,
        None    => { panic!("Failed to decode action") }
    };
    println!("Decoded action: {:?}", action);

    // 3) apply policy
    println!("Applying policy...");
    let allowed = match action {
        Action::Transfer { erc20_address, amount, .. } => {
            println!("Hex erc20 address: {:?}", hex::encode(erc20_address));

            if let Some(erc20_address) = MAX_PER_TX_MAP.get(&erc20_address) {
                println!("ERC20 address: {:?}", erc20_address);
            } else {
                println!("Unknown ERC20 address");
                return false;
            }
            println!("Amount: {:?}", amount);
            println!("Max per tx: {:?}", MAX_PER_TX_MAP.get(&erc20_address));

            if amount > *MAX_PER_TX_MAP.get(&erc20_address).unwrap() {
                false
            } else {
                true
            }
        }
    };
    println!("Policy result: {}", allowed);
    allowed
}
