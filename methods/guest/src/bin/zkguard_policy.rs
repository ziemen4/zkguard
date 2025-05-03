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
    // 1) read whichever variant the host sent
    let auth_request: AuthRequest = env::read();

    // 2) basic freshness (anti-replay)
    //if auth_request.deadline < 1_700_000_000 {
    //    env::commit(&false);
    //    return;
    //}

    // 3) pick out the raw calldata & signatures for policy
    let (calldata, sigs) = match auth_request {
        AuthRequest::Transaction { data, sigs, .. } => (data, sigs),
        AuthRequest::UserOperation { call_data, signature, .. } => (call_data, vec![signature]),
    };

    // 4) decode calldata
    let action = match parse_action(&calldata) {
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
                // check_multisig(&auth_request.tx_hash, &auth_request.sigs)
                true
            } else {
                true
            }
        }
        Action::ContractCall { .. } => {
            // check_multisig(&auth_request.tx_hash, &auth_request.sigs)
            true
        }
    };

    env::commit(&allowed);
}
