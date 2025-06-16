extern crate alloc;

use alloc::vec::Vec;
use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher, Keccak};
////////////////////////////////////////////////////////////////
//  Public constants (grouped so callers can use `constants::*`)
////////////////////////////////////////////////////////////////
pub mod constants {
    //! Values that both guest and host need.

    /// function selector for `transfer(address,uint256)`
    pub const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    /// selector for `contractCall(address,uint256,bytes)`
    pub const CONTRACTCALL_SELECTOR: [u8; 4] = [0xb6, 0x1d, 0x27, 0xf6];
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
pub enum Action {
    Transfer {
        erc20_address: [u8; 20],
        to: [u8; 20],
        amount: u128,
    },
}

/// Very small, fixed‑layout ABI decoder for the two hard‑coded
/// selectors. Returns [`Action`] on success.
pub fn parse_action<'a>(target: &[u8], data: &'a [u8]) -> Option<Action> {
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
        Some(Action::Transfer {
            erc20_address,
            to,
            amount,
        })
    } else {
        None
    }
}

/*───────────────────────────────────────────────────────────────────────────*
 *  Data Structures                                                          *
 *───────────────────────────────────────────────────────────────────────────*/

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxType {
    Transfer,
    ContractCall,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DestinationPattern {
    /// Matches any address.
    Any,
    /// Matches if the address is contained in the named group.
    Group(String),
    /// Matches if the address is contained in the named allow‑list.
    Allowlist(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignerPattern {
    /// Matches any signer.
    Any,
    /// Matches a specific address.
    Exact([u8; 20]),
    /// Matches if the signer is contained in the named group.
    Group(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AssetPattern {
    /// Wildcard – matches any asset.
    Any,
    /// Exact ERC‑20 contract address or the pseudo‑identifier for ETH.
    Exact([u8; 20]),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    Allow,
    Block,
}

/// One line in the policy (ordered by the `id` field).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyLine {
    pub id: u32, // evaluated in ascending order
    pub tx_type: TxType,
    pub destination: DestinationPattern,
    pub signer: SignerPattern,
    // ───────────────────────────────────────────────────────────────────────
    // **Minimum** is intentionally omitted for the moment – future work.
    // ───────────────────────────────────────────────────────────────────────
    pub asset: AssetPattern,
    pub action: ActionType,
}

pub type Policy = Vec<PolicyLine>; // must be stored in ascending `id` order

/// Canonical pseudo‑address used to represent native ETH transfers.
pub const ETH_ASSET: [u8; 20] = [0u8; 20];

/// Complete description of a signed user operation that is about to be
/// executed on‑chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserAction {
    pub to: [u8; 20],       // target contract or direct recipient
    pub value: u128,        // native token amount (wei)
    pub data: Vec<u8>,      // calldata (empty for plain ETH transfers)
    pub signer: [u8; 20],   // recovered signer address
    pub signature: Vec<u8>, // signature of the action
}
