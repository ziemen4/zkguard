extern crate alloc;

use alloc::string::String;
use alloc::vec::Vec;
use bincode::Options;
use serde::{Deserialize, Serialize, Deserializer, Serializer, de::Error};
use risc0_zkvm::sha::{Impl, Sha256};
use rs_merkle::Hasher as MerkleHasher;
use sha2::Digest;
use tiny_keccak::{Hasher, Keccak};
use alloy_primitives::{Address, U256, Bytes};
use alloy_sol_types::{SolValue};   

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

// ////////////////////////////////////////////////////////////////
// //  Helper types & functions
// ////////////////////////////////////////////////////////////////

/// Keccak-256 convenience wrapper (available to both sides)
pub fn keccak256(bytes: &[u8]) -> [u8; 32] {
    // Import the trait needed for the .update() and .finalize() methods
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
    Exact(#[serde(with = "serde_addr20")] [u8; 20]),
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
    Exact(#[serde(with = "serde_addr20")] [u8; 20]),
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
    Exact(#[serde(with = "serde_addr20")] [u8; 20]),
}

/// Serde helpers for an Ethereum-style 20-byte address.
/// - Human-readable formats (JSON/TOML/YAML): "0x..." hex string
/// - Binary formats (bincode): raw [u8; 20]
pub mod serde_addr20 {
    use super::*;

    pub fn serialize<S>(value: &[u8; 20], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&format!("0x{}", hex::encode(value)))
        } else {
            value.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            let s = s.strip_prefix("0x").unwrap_or(&s);
            let bytes = hex::decode(s).map_err(D::Error::custom)?;

            if bytes.len() != 20 {
                return Err(D::Error::custom(format!(
                    "expected 20-byte hex address, got {} bytes",
                    bytes.len()
                )));
            }

            let mut arr = [0u8; 20];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        } else {
            <[u8; 20]>::deserialize(deserializer)
        }
    }
}

/// Serde helpers for an optional 4-byte function selector.
/// - Human-readable formats: "0x...." or null
/// - Binary formats (bincode): Option<[u8; 4]> with raw bytes inside
pub mod serde_opt_selector4 {
    use super::*;

    pub fn serialize<S>(value: &Option<[u8; 4]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            match value {
                Some(sel) => serializer.serialize_some(&format!("0x{}", hex::encode(sel))),
                None => serializer.serialize_none(),
            }
        } else {
            value.serialize(serializer)
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 4]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            let opt = Option::<String>::deserialize(deserializer)?;
            match opt {
                Some(s) => {
                    let s = s.strip_prefix("0x").unwrap_or(&s);
                    let bytes = hex::decode(s).map_err(D::Error::custom)?;

                    if bytes.len() != 4 {
                        return Err(D::Error::custom(format!(
                            "expected 4-byte function selector, got {} bytes",
                            bytes.len()
                        )));
                    }

                    let mut arr = [0u8; 4];
                    arr.copy_from_slice(&bytes);
                    Ok(Some(arr))
                }
                None => Ok(None),
            }
        } else {
            Option::<[u8; 4]>::deserialize(deserializer)
        }
    }
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
    pub asset: AssetPattern,
    pub amount_max: Option<u128>,

    #[serde(with = "serde_opt_selector4")]
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


/// Util
pub trait HexDecodeExt {
    fn hex_decode(&self) -> Result<[u8; 20], hex::FromHexError>;
}

impl HexDecodeExt for &str {
    fn hex_decode(&self) -> Result<[u8; 20], hex::FromHexError> {
        let s = self.strip_prefix("0x").unwrap_or(self);
        let bytes = hex::decode(s)?;
        bytes.try_into().map_err(|_| hex::FromHexError::InvalidStringLength)
    }
}

/// Hashes a `UserAction` into a 32-byte digest suitable for signing.
pub fn hash_user_action_for_signing(user_action: &UserAction) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut output = [0u8; 32];

    hasher.update(&user_action.from);
    hasher.update(&user_action.to);
    hasher.update(&user_action.value.to_be_bytes());
    hasher.update(&user_action.data);
    hasher.update(&user_action.nonce.to_be_bytes());

    hasher.finalize(&mut output);
    output
}

/// Hashes a `UserAction` into a 32-byte digest using ABI encoding.
pub fn hash_abi_encoded_user_action(user_action: &UserAction) -> [u8; 32] {
    let from = Address::from(user_action.from);
    let to = Address::from(user_action.to);
    let value = U256::from(user_action.value); // widen u128 -> U256
    let nonce = U256::from(user_action.nonce); // widen u128 -> U256
    let data = Bytes::from(user_action.data.clone());

    let encoded = (from, to, value, nonce, data).abi_encode_params();
    keccak256(&encoded)
}