use alloy_sol_types::{sol, SolValue};
use anyhow::bail;
use anyhow::Result;
use bincode::Options;
use clap::Parser;
use dotenv::dotenv;
use k256::ecdsa::SigningKey;
use risc0_zkvm::sha::Digestible;
use risc0_zkvm::{default_prover, ExecutorEnv, InnerReceipt, Prover};
use rs_merkle::MerkleTree;
use serde::Deserialize;
use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;
use tiny_keccak::{Hasher, Keccak};
use tracing_subscriber::EnvFilter;
use zkguard_core::{hash_policy_line_for_merkle_tree, MerklePath, Sha256MerkleHasher, UserAction};
use zkguard_methods::{ZKGUARD_POLICY_ELF, ZKGUARD_POLICY_ID};

mod onchain_verifier;

sol! {
    struct PublicInput {
        bytes32 claimedActionHash;
        bytes32 claimedPolicyHash;
        bytes32 claimedGroupsHash;
        bytes32 claimedAllowHash;
    }
}

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    policy_file: String,
    #[clap(long)]
    groups_file: String,
    #[clap(long)]
    allowlists_file: String,
    #[clap(long)]
    rule_id: u32,
    #[clap(long)]
    from: String,
    #[clap(long)]
    to: String,
    #[clap(long)]
    value: u128,
    #[clap(long)]
    data: String,
    #[clap(long, num_args = 1..)]
    private_keys: Vec<String>,
    #[clap(long)]
    nonce: u64,
    #[clap(long)]
    verify_onchain: bool,
}

#[derive(Deserialize, Debug, Clone)]
pub struct PolicyLine {
    pub id: u32,
    pub tx_type: TxType,
    pub destination: DestinationPattern,
    pub signer: SignerPattern,
    pub asset: AssetPattern,
    pub amount_max: Option<String>,
    pub function_selector: Option<String>,
}

impl From<PolicyLine> for zkguard_core::PolicyLine {
    fn from(val: PolicyLine) -> Self {
        zkguard_core::PolicyLine {
            id: val.id,
            tx_type: val.tx_type.into(),
            destination: val.destination.into(),
            signer: val.signer.into(),
            asset: val.asset.into(),
            amount_max: val.amount_max.map(|s| s.parse::<u128>().unwrap()),
            function_selector: val.function_selector.map(|s| {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let mut arr = [0u8; 4];
                arr.copy_from_slice(&hex::decode(s).unwrap());
                arr
            }),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub enum TxType {
    Transfer,
    ContractCall,
}

impl From<TxType> for zkguard_core::TxType {
    fn from(val: TxType) -> Self {
        match val {
            TxType::Transfer => zkguard_core::TxType::Transfer,
            TxType::ContractCall => zkguard_core::TxType::ContractCall,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub enum DestinationPattern {
    Any,
    Exact(String),
    Group(String),
    Allowlist(String),
}

impl From<DestinationPattern> for zkguard_core::DestinationPattern {
    fn from(val: DestinationPattern) -> Self {
        match val {
            DestinationPattern::Any => zkguard_core::DestinationPattern::Any,
            DestinationPattern::Exact(addr) => {
                let addr = addr.strip_prefix("0x").unwrap_or(&addr);
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&hex::decode(addr).unwrap());
                zkguard_core::DestinationPattern::Exact(arr)
            }
            DestinationPattern::Group(s) => zkguard_core::DestinationPattern::Group(s),
            DestinationPattern::Allowlist(s) => zkguard_core::DestinationPattern::Allowlist(s),
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub enum SignerPattern {
    Any,
    Exact(String),
    Group(String),
    Threshold { group: String, threshold: u8 },
}

impl From<SignerPattern> for zkguard_core::SignerPattern {
    fn from(val: SignerPattern) -> Self {
        match val {
            SignerPattern::Any => zkguard_core::SignerPattern::Any,
            SignerPattern::Exact(s) => {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&hex::decode(s).unwrap());
                zkguard_core::SignerPattern::Exact(arr)
            }
            SignerPattern::Group(s) => zkguard_core::SignerPattern::Group(s),
            SignerPattern::Threshold { group, threshold } => {
                zkguard_core::SignerPattern::Threshold { group, threshold }
            }
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub enum AssetPattern {
    Any,
    Exact(String),
}

impl From<AssetPattern> for zkguard_core::AssetPattern {
    fn from(val: AssetPattern) -> Self {
        match val {
            AssetPattern::Any => zkguard_core::AssetPattern::Any,
            AssetPattern::Exact(s) => {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let mut arr = [0u8; 20];
                arr.copy_from_slice(&hex::decode(s).unwrap());
                zkguard_core::AssetPattern::Exact(arr)
            }
        }
    }
}

fn encode<T: serde::Serialize>(data: &T) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(data)
        .unwrap()
}

fn hash_user_action(ua: &UserAction) -> [u8; 32] {
    let mut h = Keccak::v256();
    let mut output = [0u8; 32];
    h.update(&ua.from);
    h.update(&ua.to);
    h.update(&ua.value.to_be_bytes());
    h.update(&ua.data);
    h.update(&ua.nonce.to_be_bytes());
    h.finalize(&mut output);
    output
}

fn decode_public_input(hex_blob: &str) -> anyhow::Result<PublicInput> {
    let bytes = hex::decode(hex_blob.strip_prefix("0x").unwrap_or(hex_blob))?;
    let decoded: PublicInput = PublicInput::abi_decode(&bytes)?;
    Ok(decoded)
}

fn print_public_input(pi: &PublicInput) {
    use alloy_primitives::B256;
    fn h(b: &B256) -> String {
        format!("0x{}", hex::encode(b.as_slice()))
    }
    println!("claimedActionHash = {}", h(&pi.claimedActionHash));
    println!("claimedPolicyHash = {}", h(&pi.claimedPolicyHash));
    println!("claimedGroupsHash = {}", h(&pi.claimedGroupsHash));
    println!("claimedAllowHash  = {}", h(&pi.claimedAllowHash));
}

pub fn encode_seal(receipt: &risc0_zkvm::Receipt) -> Result<Vec<u8>, anyhow::Error> {
    let seal = match receipt.inner.clone() {
        InnerReceipt::Fake(receipt) => {
            let seal = receipt.claim.digest().as_bytes().to_vec();
            let selector = &[0xFFu8; 4];
            let mut selector_seal = Vec::with_capacity(selector.len() + seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(&seal);
            selector_seal
        }
        InnerReceipt::Groth16(receipt) => {
            let selector = &receipt.verifier_parameters.as_bytes()[..4];
            let mut selector_seal = Vec::with_capacity(selector.len() + receipt.seal.len());
            selector_seal.extend_from_slice(selector);
            selector_seal.extend_from_slice(receipt.seal.as_ref());
            selector_seal
        }
        _ => bail!("Unsupported receipt type"),
    };
    Ok(seal)
}

async fn run_prover(
    policy: &Vec<zkguard_core::PolicyLine>,
    policy_line: &zkguard_core::PolicyLine,
    user_action: &UserAction,
    groups: &HashMap<String, Vec<[u8; 20]>>,
    allowlists: &HashMap<String, Vec<[u8; 20]>>,
    verify_onchain_flag: bool,
) -> Result<()> {
    println!("ACTION_FROM=0x{}", hex::encode(user_action.from));
    println!("ACTION_TO=0x{}", hex::encode(user_action.to));
    println!("ACTION_VALUE={}", user_action.value);
    println!("ACTION_DATA=0x{}", hex::encode(&user_action.data));
    println!("ACTION_NONCE={}", user_action.nonce);

    let mut hashed_leaves = policy
        .iter()
        .map(|pl| hash_policy_line_for_merkle_tree(pl))
        .collect::<Vec<[u8; 32]>>();

    let n = hashed_leaves.len();
    let pow2 = n.next_power_of_two();
    if pow2 > n {
        let last = *hashed_leaves.last().expect("at least one leaf");
        hashed_leaves.extend(std::iter::repeat(last).take(pow2 - n));
    }

    println!("Policy leaves:");
    for (i, h) in hashed_leaves.iter().enumerate() {
        println!("  {}: 0x{}", i, hex::encode(h));
    }
    let tree: MerkleTree<Sha256MerkleHasher> = MerkleTree::from_leaves(&hashed_leaves);
    let root = tree.root().expect("Merkle tree should have a root");
    let index = policy_line.id as u32 - 1;
    let proof = tree.proof(&[index as usize]);
    let path_hashes: Vec<[u8; 32]> = proof.proof_hashes().to_vec();

    let merkle_path = MerklePath {
        leaf_index: index as u64,
        siblings: path_hashes.clone(),
    };

    let root_bytes = encode(&root.to_vec());
    println!("Policy Merkle Root: 0x{}", hex::encode(root));
    let user_action_bytes = encode(user_action);
    let leaf_bytes = encode(policy_line);
    let path_bytes = encode(&merkle_path);
    let group_bytes = encode(groups);
    let allow_bytes = encode(allowlists);

    println!("[{}] Proving...", policy_line.id);

    let receipt = tokio::task::spawn_blocking(move || {
        let env = ExecutorEnv::builder()
            .write_frame(&root_bytes)
            .write_frame(&user_action_bytes)
            .write_frame(&leaf_bytes)
            .write_frame(&path_bytes)
            .write_frame(&group_bytes)
            .write_frame(&allow_bytes)
            .build()
            .unwrap();

        let prover = default_prover();
        prover
            .prove_with_ctx(
                env,
                &risc0_zkvm::VerifierContext::default(),
                ZKGUARD_POLICY_ELF,
                &risc0_zkvm::ProverOpts::groth16(),
            )
            .unwrap()
            .receipt
    })
    .await?;

    let journal_bytes = receipt.journal.bytes.clone();
    println!("Journal hex: 0x{}", hex::encode(&journal_bytes));
    println!("[{}] Proved!", policy_line.id);

    let onchain_seal = encode_seal(&receipt)?;
    println!("On-chain seal hex: 0x{}", hex::encode(&onchain_seal));
    println!(
        "Image ID: 0x{}",
        hex::encode(bytemuck::cast_slice(&ZKGUARD_POLICY_ID))
    );
    print_public_input(&decode_public_input(&format!(
        "0x{}",
        hex::encode(&journal_bytes)
    ))?);

    println!("[{}] Verifying...", policy_line.id);
    receipt.verify(ZKGUARD_POLICY_ID)?;
    println!("[{}] Verified!", policy_line.id);

    if verify_onchain_flag {
        println!("[{}] Verifying on-chain...", policy_line.id);
        let private_key = std::env::var("WALLET_PRIV_KEY").expect("WALLET_PRIV_KEY must be set");
        let eth_rpc_url = std::env::var("ETH_RPC_URL").expect("ETH_RPC_URL must be set");
        let contract_address = std::env::var("MODULE_ADDRESS").expect("MODULE_ADDRESS must be set");

        onchain_verifier::verify_onchain(
            &private_key,
            &eth_rpc_url,
            &contract_address,
            onchain_seal,
            journal_bytes,
            user_action.from.to_vec(),
            user_action.to.to_vec(),
            user_action.value,
            user_action.data.clone(),
            user_action.nonce,
        )
        .await?;
        println!("[{}] Verified on-chain!", policy_line.id);
    }

    Ok(())
}

fn parse_hex_address(hex_str: &str) -> Result<[u8; 20]> {
    let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
    let bytes = hex::decode(stripped)?;
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenv().ok();
    let args = Args::parse();

    let filter = EnvFilter::new("debug");
    tracing_subscriber::fmt().with_env_filter(filter).init();

    let policy_file = File::open(args.policy_file)?;
    let reader = BufReader::new(policy_file);
    let json_policy: Vec<PolicyLine> = serde_json::from_reader(reader)?;
    let policy: Vec<zkguard_core::PolicyLine> = json_policy
        .into_iter()
        .map(|policy| policy.into())
        .collect();

    let groups_file = File::open(args.groups_file)?;
    let reader = BufReader::new(groups_file);
    let json_groups: HashMap<String, Vec<String>> = serde_json::from_reader(reader)?;
    let groups: HashMap<String, Vec<[u8; 20]>> = json_groups
        .into_iter()
        .map(|(k, v)| {
            let addresses = v
                .into_iter()
                .map(|s| parse_hex_address(&s).unwrap())
                .collect();
            (k, addresses)
        })
        .collect();

    let allowlists_file = File::open(args.allowlists_file)?;
    let reader = BufReader::new(allowlists_file);
    let json_allowlists: HashMap<String, Vec<String>> = serde_json::from_reader(reader)?;
    let allowlists: HashMap<String, Vec<[u8; 20]>> = json_allowlists
        .into_iter()
        .map(|(k, v)| {
            let addresses = v
                .into_iter()
                .map(|s| parse_hex_address(&s).unwrap())
                .collect();
            (k, addresses)
        })
        .collect();

    let policy_line = policy
        .iter()
        .find(|p| p.id == args.rule_id)
        .ok_or_else(|| anyhow::anyhow!("Policy line with id {} not found", args.rule_id))?
        .clone();

    let from = parse_hex_address(&args.from)?;
    let to = parse_hex_address(&args.to)?;
    let data = hex::decode(args.data.strip_prefix("0x").unwrap_or(&args.data))?;
    let mut user_action = UserAction {
        from,
        to,
        value: args.value,
        nonce: args.nonce,
        data,
        signatures: vec![],
    };

    let message_hash = hash_user_action(&user_action);

    let mut signatures: Vec<Vec<u8>> = Vec::new();
    for pk_hex in &args.private_keys {
        let sk =
            SigningKey::from_slice(&hex::decode(pk_hex.strip_prefix("0x").unwrap_or(pk_hex))?)?;
        let (signature, recovery_id) = sk.sign_prehash_recoverable(&message_hash)?;
        let mut sig_bytes = signature.to_bytes().to_vec();
        sig_bytes.push(recovery_id.to_byte() + 27);
        signatures.push(sig_bytes);
    }

    user_action.signatures = signatures;

    run_prover(
        &policy,
        &policy_line,
        &user_action,
        &groups,
        &allowlists,
        args.verify_onchain,
    )
    .await?;

    Ok(())
}
