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
    Transfer     { erc20_address: [u8; 20], to: [u8; 20], amount: u128 },
    ContractCall { target: [u8; 20], value: u128, data: &'a [u8] },
}

/// Very small, fixed‑layout ABI decoder for the two hard‑coded
/// selectors. Returns [`Action`] on success.
pub fn parse_action<'a>(target: &[u8], data: &'a [u8]) -> Option<Action<'a>> {
    use constants::*;
    let sel = data.get(..4)?;
    if sel == TRANSFER_SELECTOR {
        println!("Data after selector: {:?}", &data[4..]);
        println!("Length of data: {:?}", data.len());

        let to: [u8; 20] = data.get(16..36)?.try_into().ok()?;

        let mut amt = [0u8; 16];
        amt.copy_from_slice(data.get(52..68)?);
        println!("Amount bytes: {:?}", amt);
        let amount = u128::from_be_bytes(amt);

        let erc20_address: [u8; 20] = target.try_into().ok()?;
        Some(Action::Transfer { erc20_address, to, amount })
    } else {
        None
    }
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
    },
    UserOperation {
        // TODO: See how to this appropriately
        data:                       Vec<u8>,
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

impl AuthRequest {
    pub fn data(&self) -> Option<&Vec<u8>> {
        match self {
            AuthRequest::Transaction { data, .. } => Some(data),
            AuthRequest::UserOperation { data, .. } => Some(data),
        }
    }

    pub fn target(&self) -> Option<&[u8; 20]> {
        match self {
            AuthRequest::Transaction { to, .. } => Some(to),
            AuthRequest::UserOperation { sender, .. } => Some(sender),
        }
    }
}