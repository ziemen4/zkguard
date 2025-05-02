#![no_std]
#![no_main]

extern crate alloc;
use alloc::vec::Vec;

use risc0_zkvm::guest::{entry, env};
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};

////////////////////////////////////////////////////////////////
//  Constants
////////////////////////////////////////////////////////////////
const TRANSFER_SELECTOR: [u8; 4]     = [0xa9, 0x05, 0x9c, 0xbb];
const CONTRACTCALL_SELECTOR: [u8; 4] = [0xb6, 0x1d, 0x27, 0xf6];

const MAX_PER_TX: u128   = 100_000_000_000_000_000;   // 0.1 ETH
const HIGH_VALUE: u128   = 50_000_000_000_000_000;    // 0.05 ETH
const REQUIRED_SIGS: usize = 2;                       // 2-of-3 policy

/// hard-coded owners for the PoC
const SIGNERS: &[[u8; 20]] = &[[0x01; 20], [0x02; 20], [0x03; 20]];

////////////////////////////////////////////////////////////////
//  Witness from the host
////////////////////////////////////////////////////////////////
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TxWitness {
    caller:   [u8; 20],
    calldata: Vec<u8>,
    value:    u128,
    tx_hash:  [u8; 32],
    sigs:     Vec<Vec<u8>>,   // 65-byte RSV each
    deadline: u64,
}

////////////////////////////////////////////////////////////////
//  Helpers
////////////////////////////////////////////////////////////////
fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(bytes);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

#[derive(Clone, Copy)]
enum Action<'a> {
    Transfer { to: [u8; 20], amount: u128 },
    ContractCall { target: [u8; 20], value: u128, data: &'a [u8] },
}

/// Very small, fixed-layout ABI decoder for our two selectors.
fn parse_action(data: &[u8]) -> Option<Action<'_>> {
    let sel = data.get(..4)?;
    if sel == TRANSFER_SELECTOR {
        let to: [u8; 20] = data.get(16..36)?.try_into().ok()?;
        let mut amt = [0u8; 16];
        amt.copy_from_slice(data.get(36..52)?);
        let amount = u128::from_be_bytes(amt);
        Some(Action::Transfer { to, amount })
    } else if sel == CONTRACTCALL_SELECTOR {
        let target: [u8; 20] = data.get(16..36)?.try_into().ok()?;
        let mut val = [0u8; 16];
        val.copy_from_slice(data.get(36..52)?);
        let value = u128::from_be_bytes(val);
        Some(Action::ContractCall { target, value, data: &data[52..] })
    } else {
        None
    }
}

/// **Stub** multisig check – merely counts signatures that *look* OK
fn check_multisig(_tx_hash: &[u8; 32], sigs: &[Vec<u8>]) -> bool {
    sigs.iter().filter(|v| v.len() == 65).count() >= REQUIRED_SIGS
}

////////////////////////////////////////////////////////////////
//  Entry
////////////////////////////////////////////////////////////////
entry!(main);
fn main() {
    let tx: TxWitness = env::read();

    // 0. basic freshness (anti-replay)
    if tx.deadline < 1_700_000_000 {
        env::commit(&false);
        return;
    }

    // 1. decode calldata
    let action = match parse_action(&tx.calldata) {
        Some(a) => a,
        None => {
            env::commit(&false);
            return;
        }
    };

    // 2. policy enforcement
    let allowed = match action {
        Action::Transfer { to: _, amount } => {
            if amount > MAX_PER_TX {
                false
            } else if amount > HIGH_VALUE {
                check_multisig(&tx.tx_hash, &tx.sigs)
            } else {
                true
            }
        }
        Action::ContractCall { .. } => check_multisig(&tx.tx_hash, &tx.sigs),
    };

    env::commit(&allowed);
}
