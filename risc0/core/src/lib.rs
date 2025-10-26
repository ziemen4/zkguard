extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use bincode::Options;
use serde::{Deserialize, Serialize};
use risc0_zkvm::sha::{Impl, Sha256};
use rs_merkle::Hasher as MerkleHasher;
use tiny_keccak::Keccak;
use sha2::Digest;
////////////////////////////////////////////////////////////////
//  Public constants (grouped so callers can use `constants::*`)
////////////////////////////////////////////////////////////////
pub mod constants {
    //! Values that both guest and host need.

    /// function selector for `transfer(address,uint256)`
    pub const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    /// selector for `contractCall(address,uint256,bytes)`
    pub const CONTRACTCALL_SELECTOR: [u8; 4] = [0xb6, 0x1d, 0x27, 0xf6];
}

////////////////////////////////////////////////////////////////
//  Helper types & functions
////////////////////////////////////////////////////////////////

/// Keccak-256 convenience wrapper (available to both sides)
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    // Import the trait needed for the .update() and .finalize() methods
    use tiny_keccak::Hasher;

    let mut k = Keccak::v256();
    k.update(bytes);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

#[derive(Clone)] // rs-merkle requires Hasher to be Clone
pub struct Sha256MerkleHasher;

impl MerkleHasher for Sha256MerkleHasher {
    type Hash = [u8; 32]; // Output type of the hash function (fixed-size array)

    fn hash(data: &[u8]) -> Self::Hash {
        // Convert the resulting byte slice `&[u8]` into a fixed-size array `[u8; 32]`
        Impl::hash_bytes(data).as_bytes().try_into().unwrap()
    }
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

/// Very small, fixed-layout ABI decoder for the two hard-coded
/// selectors. Returns [`Action`] on success.
pub fn parse_action<'a>(target: &[u8], data: &'a [u8]) -> Option<Action> {
    use constants::*;
    let sel = data.get(..4)?;

    if sel == TRANSFER_SELECTOR {
        let to: [u8; 20] = data.get(16..36)?.try_into().ok()?;

        let mut amt = [0u8; 16];
        amt.copy_from_slice(data.get(52..68)?);
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

// It bincode-serializes the PolicyLine and then hashes the resulting bytes.
// This ensures consistency between host (building tree) and guest (verifying leaf hash).
pub fn hash_policy_line_for_merkle_tree(pl: &PolicyLine) -> [u8; 32] {
    // Serialize the PolicyLine into bytes.
    let policy_line_bytes = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(pl)
        .expect("Failed to bincode serialize PolicyLine for hashing");

    // Hash the resulting bytes using the standard `sha2` crate.
    sha2::Sha256::digest(&policy_line_bytes).into()
}

/*───────────────────────────────────────────────────────────────────────────*
 * Data Structures                                                          *
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
    /// Matches a specific address.
    Exact([u8; 20]),
    /// Matches if the address is contained in the named group.
    Group(String),
    /// Matches if the address is contained in the named allow-list.
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
    /// Matches if a threshold of signers from the named group have signed.
    Threshold { group: String, threshold: u8 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AssetPattern {
    /// Wildcard – matches any asset.
    Any,
    /// Exact ERC-20 contract address or the pseudo-identifier for ETH.
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
    // **Minimum** is intentionally omitted for the moment – future work.
    // ───────────────────────────────────────────────────────────────────────
    pub asset: AssetPattern,
    pub amount_max: Option<u128>,
    pub function_selector: Option<[u8; 4]>,
}

/// Canonical pseudo-address used to represent native ETH transfers.
pub const ETH_ASSET: [u8; 20] = [0u8; 20];

/// Complete description of a signed user operation that is about to be
/// executed on-chain
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserAction {
    pub from: [u8; 20],           // contract address initiating the action
    pub to: [u8; 20],               // target contract or direct recipient
    pub value: u128,                // native token amount (wei)
    pub nonce: u64,                // Safe's current nonce for replay protection
    pub data: Vec<u8>,              // calldata (empty for plain ETH transfers)
    pub signatures: Vec<Vec<u8>>,   // one or more Ethereum-style signatures (65 bytes each)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerklePath {
    pub leaf_index: u64,         // The 0-based index of the leaf from the left
    pub siblings: Vec<[u8; 32]>, // The sibling hashes from bottom to top
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInputs {
    root: [u8; 32],
    action: UserAction,
}
