// noir/src/policy.nr

// Global constants for fixed-size arrays, a necessity for ZK circuits.
pub global MAX_CALLDATA_SIZE: u32 = 256;
pub global MAX_SIGNATURES: u32 = 5;
pub global SIGNATURE_SIZE: u32 = 65;

// Constants to represent enum variants for TxType
pub global TX_TYPE_TRANSFER: Field = 0;
pub global TX_TYPE_CONTRACT_CALL: Field = 1;

// Constants for DestinationPattern variants
pub global DEST_PATTERN_ANY: Field = 0;
pub global DEST_PATTERN_GROUP: Field = 1;
pub global DEST_PATTERN_ALLOWLIST: Field = 2;
pub global DEST_PATTERN_EXACT: Field = 3;

// Constants for SignerPattern variants
pub global SIGNER_PATTERN_ANY: Field = 0;
pub global SIGNER_PATTERN_EXACT: Field = 1;
pub global SIGNER_PATTERN_GROUP: Field = 2;
pub global SIGNER_PATTERN_THRESHOLD: Field = 3;

// Constants for AssetPattern variants
pub global ASSET_PATTERN_ANY: Field = 0;
pub global ASSET_PATTERN_EXACT: Field = 1;

// Represents the DestinationPattern enum from the Rust code.
// The `kind` field acts as a discriminator.
pub struct DestinationPattern {
    pub kind: Field,
    // Used for Group and Allowlist kinds. Represents the keccak256 hash of the name.
    pub name_hash: Field,
    // For Exact kind: the destination address to match against.
    // Ignored for ANY/GROUP/ALLOWLIST.
    pub address: [u8; 20],
}

// Represents the SignerPattern enum.
pub struct SignerPattern {
    pub kind: Field,
    // For `Exact` kind: the required signer's address.
    pub address: [u8; 20],
    // For `Group` or `Threshold` kinds: keccak256 hash of the group name.
    pub group_name_hash: Field,
    // For `Threshold` kind: the minimum number of required signatures.
    pub threshold: u8,
}

// Represents the AssetPattern enum.
pub struct AssetPattern {
    pub kind: Field,
    // For `Exact` kind: the asset's contract address.
    pub address: [u8; 20],
}

// A single policy rule, equivalent to the Rust `PolicyLine` struct.
pub struct PolicyLine {
    pub id: u32,
    // The type of transaction this rule applies to (e.g., Transfer, ContractCall).
    pub tx_type: Field,
    pub destination: DestinationPattern,
    pub signer: SignerPattern,
    pub asset: AssetPattern,
    // `Option<u128>` is modeled with a boolean flag and the value.
    pub has_amount_max: bool,
    pub amount_max: Field, // u128 fits within a Field.
    // `Option<[u8; 4]>` is also modeled with a flag.
    pub has_function_selector: bool,
    pub function_selector: [u8; 4],
}

// A user's action to be verified against a policy.
// Dynamic vectors from Rust are converted to fixed-size arrays.
pub struct UserAction {
    pub from: [u8; 20],
    pub to: [u8; 20],
    pub value: Field, // u128 for native token value.
    // Calldata for the transaction.
    pub data: [u8; MAX_CALLDATA_SIZE],
    pub data_len: u32,
    // Signatures authorizing the action.
    pub signatures: [[u8; SIGNATURE_SIZE]; MAX_SIGNATURES],
    pub signature_count: u32,
}
