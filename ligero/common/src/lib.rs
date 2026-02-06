use serde::{de::Error as DeError, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;

pub type AddressBook = BTreeMap<String, Vec<[u8; 20]>>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TxType {
    Transfer,
    ContractCall,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DestinationPattern {
    Any,
    Exact(#[serde(with = "serde_addr20")] [u8; 20]),
    Group(String),
    Allowlist(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignerPattern {
    Any,
    Exact(#[serde(with = "serde_addr20")] [u8; 20]),
    Group(String),
    Threshold { group: String, threshold: u8 },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AssetPattern {
    Any,
    Exact(#[serde(with = "serde_addr20")] [u8; 20]),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyLine {
    pub id: u32,
    pub tx_type: TxType,
    pub destination: DestinationPattern,
    pub signer: SignerPattern,
    pub asset: AssetPattern,
    pub amount_max: Option<u128>,
    #[serde(with = "serde_opt_selector4")]
    pub function_selector: Option<[u8; 4]>,
}

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
            parse_hex_address(&s).map_err(D::Error::custom)
        } else {
            <[u8; 20]>::deserialize(deserializer)
        }
    }
}

pub mod serde_opt_selector4 {
    use super::*;

    pub fn serialize<S>(value: &Option<[u8; 4]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if serializer.is_human_readable() {
            match value {
                Some(selector) => serializer.serialize_some(&format!("0x{}", hex::encode(selector))),
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
            match Option::<String>::deserialize(deserializer)? {
                Some(s) => {
                    let bytes = parse_hex_bytes(&s).map_err(D::Error::custom)?;
                    if bytes.len() != 4 {
                        return Err(D::Error::custom(format!(
                            "expected 4-byte selector, got {} bytes",
                            bytes.len()
                        )));
                    }
                    let mut out = [0u8; 4];
                    out.copy_from_slice(&bytes);
                    Ok(Some(out))
                }
                None => Ok(None),
            }
        } else {
            Option::<[u8; 4]>::deserialize(deserializer)
        }
    }
}

pub fn parse_hex_address(input: &str) -> Result<[u8; 20], String> {
    let bytes = parse_hex_bytes(input)?;
    if bytes.len() != 20 {
        return Err(format!(
            "expected 20-byte address, got {} bytes",
            bytes.len()
        ));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn parse_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    let stripped = input.strip_prefix("0x").unwrap_or(input);
    if stripped.is_empty() {
        return Ok(Vec::new());
    }
    let normalized = if stripped.len() % 2 == 1 {
        format!("0{}", stripped)
    } else {
        stripped.to_owned()
    };
    hex::decode(normalized).map_err(|e| format!("invalid hex value: {e}"))
}

pub fn bytes_to_hex_prefixed(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}
