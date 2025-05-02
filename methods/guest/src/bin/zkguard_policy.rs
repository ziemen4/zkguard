#![no_main]

risc0_zkvm::guest::entry!(main);

use risc0_zkvm::guest::env;
use serde::{Deserialize, Serialize};

/// Exactly the same struct the host sends.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Input {
    to:    [u8; 20],
    value: u128,
}

// === Simple hard-coded policy demo ===========================
//   * address must be in ALLOWLIST
//   * value <= MAX_TRANSFER
// =============================================================
const MAX_TRANSFER: u128 = 100_000_000_000_000_000;    // 0.1 ETH
const ALLOWLIST: [[u8; 20]; 1] = [[
    0x12, 0x34, 0x56, 0x78, 0x90,
    0xab, 0xcd, 0xef, 0x12, 0x34,
    0x56, 0x78, 0x90, 0xab, 0xcd,
    0xef, 0x12, 0x34, 0x56, 0x78,
]];

fn main() {
    // Read the caller-supplied transaction data
    println!("Reading input...");
    let tx: Input = env::read();                // read same binary
    println!("Input: {:?}", tx);

    // Evaluate the policy
    let allowed =
        ALLOWLIST.contains(&tx.to) && tx.value <= MAX_TRANSFER;

    // Commit the boolean result to the journal
    env::commit(&allowed);
}
