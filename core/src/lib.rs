extern crate alloc;

use alloc::vec::Vec;
use serde::{Serialize, Deserialize};
use tiny_keccak::{Hasher, Keccak};

////////////////////////////////////////////////////////////////
//  Public constants (grouped so callers can use `constants::*`)
////////////////////////////////////////////////////////////////
pub mod constants {
    //! Values that both guest and host need.

    /// function selector for `transfer(address,uint256)`
    pub const TRANSFER_SELECTOR:       [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    /// selector for `contractCall(address,uint256,bytes)`
    pub const CONTRACTCALL_SELECTOR:   [u8; 4] = [0xb6, 0x1d, 0x27, 0xf6];

    pub const MAX_PER_TX:   u128  = 100_000_000_000_000_000;   // 0.1 ETH
    pub const HIGH_VALUE:   u128  = 50_000_000_000_000_000;    // 0.05 ETH
    pub const REQUIRED_SIGS: usize = 2;                        // 2‑of‑3 multisig

    /// Hard‑coded owners for the PoC
    pub const SIGNERS: &[[u8; 20]] = &[[0x01; 20], [0x02; 20], [0x03; 20]];
}

////////////////////////////////////////////////////////////////
//  Helper types & functions
////////////////////////////////////////////////////////////////

/// Keccak‑256 convenience wrapper (available to both sides)
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(bytes);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

/// Compact action enum produced by [`parse_action`]
#[derive(Clone, Copy, Debug)]
pub enum Action<'a> {
    Transfer     { to: [u8; 20], amount: u128 },
    ContractCall { target: [u8; 20], value: u128, data: &'a [u8] },
}

/// Very small, fixed‑layout ABI decoder for the two hard‑coded
/// selectors. Returns [`Action`] on success.
pub fn parse_action(data: &[u8]) -> Option<Action<'_>> {
    use constants::*;
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
pub fn check_multisig(_tx_hash: &[u8; 32], sigs: &[Vec<u8>]) -> bool {
    sigs.iter().filter(|v| v.len() == 65).count() >= constants::REQUIRED_SIGS
}

////////////////////////////////////////////////////////////////
//  Unified request type (shared between host & guest)
////////////////////////////////////////////////////////////////

/// Either a normal EOA transaction *or* an ERC‑4337 UserOperation.
///
/// We keep everything in compact numeric form; any JSON / ABI
/// decoding happens at the outer edges of the system.
#[derive(Serialize, Deserialize, Debug)]
pub enum AuthRequest {
    Transaction {
        from:   [u8; 20],
        to:     [u8; 20],
        value:  u128,
        data:   Vec<u8>,
        sigs:   Vec<Vec<u8>>,
    },
    UserOperation {
        sender:                     [u8; 20],
        nonce:                      u128,
        factory:                    [u8; 20],
        factory_data:               Vec<u8>,
        call_data:                  Vec<u8>,
        call_gas_limit:             u128,
        verification_gas_limit:     u128,
        pre_verification_gas:       u128,
        max_fee_per_gas:            u128,
        max_priority_fee_per_gas:   u128,
        paymaster:                  [u8; 20],
        paymaster_verification_gas_limit: u128,
        paymaster_post_op_gas_limit:      u128,
        paymaster_data:             Vec<u8>,
        signature:                  Vec<u8>,
    },
}
