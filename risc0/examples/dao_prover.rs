
use anyhow::Result;
use bincode::Options;
use clap::Parser;
use dotenv::dotenv;
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::rand_core::OsRng;
use risc0_zkvm::{default_prover, ExecutorEnv};
use rs_merkle::MerkleTree;
use std::collections::HashMap;
use tiny_keccak::{Hasher, Keccak};
use zkguard_core::{
    hash_policy_line_for_merkle_tree, AssetPattern, DestinationPattern, MerklePath, PolicyLine,
    Sha256MerkleHasher, SignerPattern, TxType, UserAction,
};
use zkguard_methods::{ZKGUARD_POLICY_ELF, ZKGUARD_POLICY_ID};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    #[clap(long)]
    example: String,
}

// Helper to bincode-encode with fixint
fn encode<T: serde::Serialize>(data: &T) -> Vec<u8> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .serialize(data)
        .unwrap()
}

fn hash_user_action(ua: &UserAction) -> [u8; 32] {
    let mut h = Keccak::v256();
    let mut output = [0u8; 32];
    h.update(&ua.to);
    h.update(&ua.value.to_be_bytes());
    h.update(&ua.data);
    h.finalize(&mut output);
    output
}

const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

fn run_prover(
    policy_line: &PolicyLine,
    user_action: &UserAction,
    groups: &HashMap<String, Vec<[u8; 20]>>,
    allowlists: &HashMap<String, Vec<[u8; 20]>>,
) -> Result<()> {
    let hashed_leaves = vec![hash_policy_line_for_merkle_tree(policy_line)];
    let tree: MerkleTree<Sha256MerkleHasher> = MerkleTree::from_leaves(&hashed_leaves);
    let root = tree.root().expect("Merkle tree should have a root");
    let proof = tree.proof(&[0]);
    let path_hashes: Vec<[u8; 32]> = proof.proof_hashes().to_vec();

    let merkle_path = MerklePath {
        leaf_index: 0u64,
        siblings: path_hashes.clone(),
    };

    let root_bytes = encode(&root.to_vec());
    let user_action_bytes = encode(user_action);
    let leaf_bytes = encode(policy_line);
    let path_bytes = encode(&merkle_path);
    let group_bytes = encode(groups);
    let allow_bytes = encode(allowlists);

    let env = ExecutorEnv::builder()
        .write_frame(&root_bytes)
        .write_frame(&user_action_bytes)
        .write_frame(&leaf_bytes)
        .write_frame(&path_bytes)
        .write_frame(&group_bytes)
        .write_frame(&allow_bytes)
        .build()?;

    println!("[{}] Proving...", policy_line.id);
    let prover = default_prover();
    let receipt = prover.prove(env, ZKGUARD_POLICY_ELF)?.receipt;
    println!("[{}] Proved!", policy_line.id);

    println!("[{}] Verifying...", policy_line.id);
    receipt.verify(ZKGUARD_POLICY_ID)?;
    println!("[{}] Verified!", policy_line.id);

    Ok(())
}

fn main() -> Result<()> {
    dotenv().ok();
    let args = Args::parse();

    let sk = SigningKey::random(&mut OsRng);
    let pk_bytes = sk.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec();
    let mut hasher = Keccak::v256();
    let mut pk_hash = [0u8; 32];
    hasher.update(&pk_bytes);
    hasher.finalize(&mut pk_hash);
    let from_addr: [u8; 20] = pk_hash[12..].try_into()?;
    let our_dao_safe_address: [u8; 20] = from_addr;

    // Define the second signer's private key
    let sk2_hex = "2222222222222222222222222222222222222222222222222222222222222222";
    let sk2 = SigningKey::from_slice(&hex::decode(sk2_hex).unwrap()).unwrap();
    
    // Derive the second signer's address
    let pk_bytes2 = sk2.verifying_key().to_encoded_point(false).as_bytes()[1..].to_vec();
    let mut hasher2 = Keccak::v256();
    let mut pk_hash2 = [0u8; 32];
    hasher2.update(&pk_bytes2);
    hasher2.finalize(&mut pk_hash2);
    let governance_signer_1: [u8; 20] = pk_hash2[12..].try_into()?;

    let team_wallet_1: [u8; 20] = hex::decode("1111111111111111111111111111111111111111")?.try_into().unwrap();
    let approved_dex_1: [u8; 20] = hex::decode("3333333333333333333333333333333333333333")?.try_into().unwrap();
    let approved_lending_1: [u8; 20] = hex::decode("4444444444444444444444444444444444444444")?.try_into().unwrap();
    let usdc_addr: [u8; 20] = hex::decode("A0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")?.try_into().unwrap();
    let weth_addr: [u8; 20] = hex::decode("C02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2")?.try_into().unwrap();

    let mut groups: HashMap<String, Vec<[u8; 20]>> = HashMap::new();
    groups.insert("TeamWallets".to_string(), vec![team_wallet_1]);
    groups.insert("GovernanceSigners".to_string(), vec![governance_signer_1, from_addr]);

    let mut allowlists: HashMap<String, Vec<[u8; 20]>> = HashMap::new();
    allowlists.insert("ApprovedDEXs".to_string(), vec![approved_dex_1]);
    allowlists.insert("ApprovedLendingProtocols".to_string(), vec![approved_lending_1]);
    allowlists.insert("ApprovedStablecoins".to_string(), vec![usdc_addr]);
    allowlists.insert("ApprovedBlueChipAssets".to_string(), vec![weth_addr]);

    match args.example.as_str() {
        "contributor_payments" => {
            let policy = PolicyLine {
                id: 1,
                tx_type: TxType::Transfer,
                destination: DestinationPattern::Group("TeamWallets".to_string()),
                signer: SignerPattern::Exact(our_dao_safe_address),
                asset: AssetPattern::Exact(usdc_addr),
                amount_max: None,
                function_selector: None,
            };
            let amount: u128 = 5000_000000; // 5000 USDC
            let mut data = TRANSFER_SELECTOR.to_vec();
            data.extend([0u8; 12]);
            data.extend(&team_wallet_1);
            data.extend([0u8; 16]);
            data.extend(&amount.to_be_bytes());
            let mut user_action = UserAction { to: usdc_addr, value: 0, data, signatures: vec![] };
            let message_hash = hash_user_action(&user_action);
            let (signature, recovery_id) = sk.sign_prehash_recoverable(&message_hash)?;
            let mut sig_bytes = signature.to_bytes().to_vec();
            sig_bytes.push(recovery_id.to_byte() + 27);
            user_action.signatures = vec![sig_bytes];
            run_prover(&policy, &user_action, &groups, &allowlists)?;
        }
        "defi_swaps" => {
            let policy = PolicyLine {
                id: 2,
                tx_type: TxType::ContractCall,
                destination: DestinationPattern::Allowlist("ApprovedDEXs".to_string()),
                signer: SignerPattern::Exact(our_dao_safe_address),
                asset: AssetPattern::Any,
                amount_max: None,
                function_selector: None,
            };
            let mut user_action = UserAction { to: approved_dex_1, value: 0, data: vec![0x7f, 0xf3, 0x6a, 0xb5], signatures: vec![] };
            let message_hash = hash_user_action(&user_action);
            let (signature, recovery_id) = sk.sign_prehash_recoverable(&message_hash)?;
            let mut sig_bytes = signature.to_bytes().to_vec();
            sig_bytes.push(recovery_id.to_byte() + 27);
            user_action.signatures = vec![sig_bytes];
            run_prover(&policy, &user_action, &groups, &allowlists)?;
        }
        "supply_lending" => {
            let policy = PolicyLine {
                id: 3,
                tx_type: TxType::Transfer,
                destination: DestinationPattern::Allowlist("ApprovedLendingProtocols".to_string()),
                signer: SignerPattern::Exact(our_dao_safe_address),
                asset: AssetPattern::Exact(weth_addr),
                amount_max: None,
                function_selector: None,
            };
            let amount: u128 = 10_000_000_000_000_000_000; // 10 WETH
            let mut data = TRANSFER_SELECTOR.to_vec();
            data.extend([0u8; 12]);
            data.extend(&approved_lending_1);
            data.extend([0u8; 16]);
            data.extend(&amount.to_be_bytes());
            let mut user_action = UserAction { to: weth_addr, value: 0, data, signatures: vec![] };
            let message_hash = hash_user_action(&user_action);
            let (signature, recovery_id) = sk.sign_prehash_recoverable(&message_hash)?;
            let mut sig_bytes = signature.to_bytes().to_vec();
            sig_bytes.push(recovery_id.to_byte() + 27);
            user_action.signatures = vec![sig_bytes];
            run_prover(&policy, &user_action, &groups, &allowlists)?;
        }
        "interact_dapps" => {
            let policy = PolicyLine {
                id: 4,
                tx_type: TxType::ContractCall,
                destination: DestinationPattern::Allowlist("ApprovedLendingProtocols".to_string()),
                signer: SignerPattern::Exact(our_dao_safe_address),
                asset: AssetPattern::Any,
                amount_max: None,
                function_selector: None,
            };
            let mut user_action = UserAction { to: approved_lending_1, value: 0, data: vec![0x12, 0x34, 0x56, 0x78], signatures: vec![] };
            let message_hash = hash_user_action(&user_action);
            let (signature, recovery_id) = sk.sign_prehash_recoverable(&message_hash)?;
            let mut sig_bytes = signature.to_bytes().to_vec();
            sig_bytes.push(recovery_id.to_byte() + 27);
            user_action.signatures = vec![sig_bytes];
            run_prover(&policy, &user_action, &groups, &allowlists)?;
        }
        "amount_limits" => {
            let policy = PolicyLine {
                id: 5,
                tx_type: TxType::Transfer,
                destination: DestinationPattern::Group("TeamWallets".to_string()),
                signer: SignerPattern::Exact(our_dao_safe_address),
                asset: AssetPattern::Exact(usdc_addr),
                amount_max: Some(10000_000000), // 10,000 USDC
                function_selector: None,
            };
            let amount: u128 = 9000_000000; // 9,000 USDC (within limit)
            let mut data = TRANSFER_SELECTOR.to_vec();
            data.extend([0u8; 12]);
            data.extend(&team_wallet_1);
            data.extend([0u8; 16]);
            data.extend(&amount.to_be_bytes());
            let mut user_action = UserAction { to: usdc_addr, value: 0, data, signatures: vec![] };
            let message_hash = hash_user_action(&user_action);
            let (signature, recovery_id) = sk.sign_prehash_recoverable(&message_hash)?;
            let mut sig_bytes = signature.to_bytes().to_vec();
            sig_bytes.push(recovery_id.to_byte() + 27);
            user_action.signatures = vec![sig_bytes];
            run_prover(&policy, &user_action, &groups, &allowlists)?;
        }
        "function_level_controls" => {
            let policy = PolicyLine {
                id: 6,
                tx_type: TxType::ContractCall,
                destination: DestinationPattern::Allowlist("ApprovedDEXs".to_string()),
                signer: SignerPattern::Exact(our_dao_safe_address),
                asset: AssetPattern::Any,
                amount_max: None,
                function_selector: Some([0x7f, 0xf3, 0x6a, 0xb5]), // swapExactETHForTokens
            };
            let mut user_action = UserAction { to: approved_dex_1, value: 0, data: vec![0x7f, 0xf3, 0x6a, 0xb5], signatures: vec![] };
            let message_hash = hash_user_action(&user_action);
            let (signature, recovery_id) = sk.sign_prehash_recoverable(&message_hash)?;
            let mut sig_bytes = signature.to_bytes().to_vec();
            sig_bytes.push(recovery_id.to_byte() + 27);
            user_action.signatures = vec![sig_bytes];
            run_prover(&policy, &user_action, &groups, &allowlists)?;
        }
        "advanced_signer_policies" => {
            let policy = PolicyLine {
                id: 7,
                tx_type: TxType::ContractCall,
                destination: DestinationPattern::Allowlist("ApprovedDEXs".to_string()),
                signer: SignerPattern::Threshold { group: "GovernanceSigners".to_string(), threshold: 2 },
                asset: AssetPattern::Any,
                amount_max: None,
                function_selector: None,
            };
            let mut user_action = UserAction { to: approved_dex_1, value: 0, data: vec![], signatures: vec![] };
            let message_hash = hash_user_action(&user_action);

            let (signature1, recovery_id1) = sk.sign_prehash_recoverable(&message_hash)?;
            let mut sig_bytes1 = signature1.to_bytes().to_vec();
            sig_bytes1.push(recovery_id1.to_byte() + 27);

            let sk2 = SigningKey::from_slice(&hex::decode("2222222222222222222222222222222222222222222222222222222222222222").unwrap()).unwrap();
            let (signature2, recovery_id2) = sk2.sign_prehash_recoverable(&message_hash)?;
            let mut sig_bytes2 = signature2.to_bytes().to_vec();
            sig_bytes2.push(recovery_id2.to_byte() + 27);

            user_action.signatures = vec![sig_bytes1, sig_bytes2];
            run_prover(&policy, &user_action, &groups, &allowlists)?;
        }
        _ => {
            println!("Unknown example: {}", args.example);
        }
    }

    Ok(())
}
