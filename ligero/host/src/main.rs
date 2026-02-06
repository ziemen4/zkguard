use anyhow::{bail, Context, Result};
use clap::Parser;
use k256::ecdsa::SigningKey;
use serde_json::json;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use tiny_keccak::{Hasher, Keccak};
use zkguard_ligero_common::{
    bytes_to_hex_prefixed, parse_hex_address, parse_hex_bytes, AddressBook, AssetPattern,
    DestinationPattern, PolicyLine, SignerPattern, TxType,
};

#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Args {
    #[arg(long)]
    policy_file: PathBuf,
    #[arg(long)]
    groups_file: PathBuf,
    #[arg(long)]
    allowlists_file: PathBuf,
    #[arg(long)]
    rule_id: u32,
    #[arg(long)]
    from: String,
    #[arg(long)]
    to: String,
    #[arg(long)]
    value: u128,
    #[arg(long)]
    data: String,
    #[arg(long)]
    nonce: u64,
    #[arg(long, num_args = 1..)]
    private_keys: Vec<String>,
    #[arg(long)]
    program: String,
    #[arg(long)]
    shader_path: String,
    #[arg(long, default_value_t = 8192)]
    packing: u64,
    #[arg(long)]
    private_indices: Vec<usize>,
    #[arg(long, default_value_t = false)]
    obscure_private: bool,
    #[arg(long, default_value = "ligero_prover_input.json")]
    prover_out: PathBuf,
    #[arg(long, default_value = "ligero_verifier_input.json")]
    verifier_out: PathBuf,
}

#[derive(Clone)]
enum ArgValue {
    Hex(Vec<u8>),
    I64(i64),
}

#[derive(Clone)]
struct FlattenedRule {
    id: i64,
    tx_type: i64,
    destination_mode: i64,
    destination_exact: [u8; 20],
    destination_list: Vec<[u8; 20]>,
    destination_list_hash: [u8; 32],
    signer_mode: i64,
    signer_exact: [u8; 20],
    signer_list: Vec<[u8; 20]>,
    signer_list_hash: [u8; 32],
    signer_threshold: i64,
    asset_mode: i64,
    asset_exact: [u8; 20],
    amount_max: i64,
    has_selector: i64,
    selector: [u8; 4],
    leaf_hash: [u8; 32],
}

fn parse_address_book(path: &PathBuf) -> Result<AddressBook> {
    let file = File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let reader = BufReader::new(file);
    let raw: BTreeMap<String, Vec<String>> = serde_json::from_reader(reader)
        .with_context(|| format!("invalid JSON in {}", path.display()))?;

    let mut out: AddressBook = BTreeMap::new();
    for (name, values) in raw {
        let mut addresses = Vec::with_capacity(values.len());
        for value in values {
            let parsed =
                parse_hex_address(&value).map_err(anyhow::Error::msg).with_context(|| {
                    format!("invalid address '{}' in list '{}'", value, name)
                })?;
            addresses.push(parsed);
        }
        addresses.sort();
        addresses.dedup();
        out.insert(name, addresses);
    }

    Ok(out)
}

fn mix_hash(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut state: u64 = 0x243f6a8885a308d3;
    let mut i = 0usize;
    while i < data.len() {
        let byte = data[i];
        state ^= (byte as u64)
            .wrapping_add(0x9e3779b97f4a7c15)
            .wrapping_add(state << 6)
            .wrapping_add(state >> 2);

        let idx = i & 31;
        out[idx] = out[idx].wrapping_add((state as u8) ^ byte);
        out[(idx + 11) & 31] ^= (state >> 16) as u8;
        i += 1;
    }

    out[0] ^= (data.len() & 0xff) as u8;
    out[31] ^= ((data.len() >> 8) & 0xff) as u8;
    out
}

fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut blob = [0u8; 65];
    blob[0] = 1;
    blob[1..33].copy_from_slice(left);
    blob[33..65].copy_from_slice(right);
    mix_hash(&blob)
}

fn hash_address_list(addresses: &[[u8; 20]]) -> [u8; 32] {
    let mut blob = Vec::with_capacity(1 + 8 + addresses.len() * 20);
    blob.push(0x4c);
    blob.extend_from_slice(&(addresses.len() as i64).to_le_bytes());
    for addr in addresses {
        blob.extend_from_slice(addr);
    }
    mix_hash(&blob)
}

fn hash_flattened_rule(rule: &FlattenedRule) -> [u8; 32] {
    let mut blob = Vec::with_capacity(1 + 8 * 13 + 20 * 3 + 32 * 2 + 4);
    blob.push(0x52);
    blob.extend_from_slice(&rule.id.to_le_bytes());
    blob.extend_from_slice(&rule.tx_type.to_le_bytes());
    blob.extend_from_slice(&rule.destination_mode.to_le_bytes());
    blob.extend_from_slice(&rule.destination_exact);
    blob.extend_from_slice(&rule.destination_list_hash);
    blob.extend_from_slice(&rule.signer_mode.to_le_bytes());
    blob.extend_from_slice(&rule.signer_exact);
    blob.extend_from_slice(&rule.signer_list_hash);
    blob.extend_from_slice(&rule.signer_threshold.to_le_bytes());
    blob.extend_from_slice(&rule.asset_mode.to_le_bytes());
    blob.extend_from_slice(&rule.asset_exact);
    blob.extend_from_slice(&rule.amount_max.to_le_bytes());
    blob.extend_from_slice(&rule.has_selector.to_le_bytes());
    blob.extend_from_slice(&rule.selector);
    mix_hash(&blob)
}

fn require_named_list<'a>(book: &'a AddressBook, list_name: &str, field_name: &str) -> Result<&'a Vec<[u8; 20]>> {
    book.get(list_name).with_context(|| format!("missing {field_name} list '{list_name}'"))
}

fn flatten_rule(rule: &PolicyLine, groups: &AddressBook, allowlists: &AddressBook) -> Result<FlattenedRule> {
    let id = i64::from(rule.id);
    let tx_type = match rule.tx_type {
        TxType::Transfer => 0,
        TxType::ContractCall => 1,
    };

    let mut destination_mode = 0i64;
    let mut destination_exact = [0u8; 20];
    let mut destination_list: Vec<[u8; 20]> = Vec::new();
    match &rule.destination {
        DestinationPattern::Any => {}
        DestinationPattern::Exact(addr) => {
            destination_mode = 1;
            destination_exact = *addr;
        }
        DestinationPattern::Group(name) => {
            destination_mode = 2;
            destination_list = require_named_list(groups, name, "group")?.clone();
        }
        DestinationPattern::Allowlist(name) => {
            destination_mode = 2;
            destination_list = require_named_list(allowlists, name, "allowlist")?.clone();
        }
    }
    let destination_list_hash = hash_address_list(&destination_list);

    let mut signer_mode = 0i64;
    let mut signer_exact = [0u8; 20];
    let mut signer_list: Vec<[u8; 20]> = Vec::new();
    let mut signer_threshold = 0i64;
    match &rule.signer {
        SignerPattern::Any => {}
        SignerPattern::Exact(addr) => {
            signer_mode = 1;
            signer_exact = *addr;
        }
        SignerPattern::Group(name) => {
            signer_mode = 2;
            signer_list = require_named_list(groups, name, "group")?.clone();
        }
        SignerPattern::Threshold { group, threshold } => {
            signer_mode = 3;
            signer_list = require_named_list(groups, group, "group")?.clone();
            signer_threshold = i64::from(*threshold);
        }
    }
    let signer_list_hash = hash_address_list(&signer_list);

    let (asset_mode, asset_exact) = match rule.asset {
        AssetPattern::Any => (0, [0u8; 20]),
        AssetPattern::Exact(addr) => (1, addr),
    };

    let amount_max = match rule.amount_max {
        Some(value) => i64::try_from(value).context("amount_max exceeds i64::MAX")?,
        None => -1,
    };

    let (has_selector, selector) = match rule.function_selector {
        Some(sel) => (1, sel),
        None => (0, [0u8; 4]),
    };

    let mut flattened = FlattenedRule {
        id,
        tx_type,
        destination_mode,
        destination_exact,
        destination_list,
        destination_list_hash,
        signer_mode,
        signer_exact,
        signer_list,
        signer_list_hash,
        signer_threshold,
        asset_mode,
        asset_exact,
        amount_max,
        has_selector,
        selector,
        leaf_hash: [0u8; 32],
    };
    flattened.leaf_hash = hash_flattened_rule(&flattened);
    Ok(flattened)
}

fn merkle_root_and_path(leaves: &[[u8; 32]], index: usize) -> Result<([u8; 32], Vec<[u8; 32]>)> {
    if leaves.is_empty() {
        bail!("cannot build merkle tree from zero leaves");
    }
    if index >= leaves.len() {
        bail!("leaf index {} out of range {}", index, leaves.len());
    }

    let mut level = leaves.to_vec();
    let mut idx = index;
    let mut siblings = Vec::new();

    while level.len() > 1 {
        if level.len() % 2 != 0 {
            bail!("merkle level has odd length {}; leaves must be power-of-two padded", level.len());
        }

        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        siblings.push(level[sibling_idx]);

        let mut next = Vec::with_capacity(level.len() / 2);
        for pair in level.chunks_exact(2) {
            next.push(hash_pair(&pair[0], &pair[1]));
        }
        idx /= 2;
        level = next;
    }

    Ok((level[0], siblings))
}

fn flatten_addresses(addrs: &[[u8; 20]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(addrs.len() * 20);
    for addr in addrs {
        out.extend_from_slice(addr);
    }
    out
}

fn private_key_to_address(private_key_hex: &str) -> Result<[u8; 20]> {
    let key_bytes = parse_hex_bytes(private_key_hex).map_err(anyhow::Error::msg)?;
    let signing_key = SigningKey::from_slice(&key_bytes).context("invalid private key bytes")?;
    let pubkey = signing_key.verifying_key().to_encoded_point(false);

    let mut keccak_out = [0u8; 32];
    let mut hasher = Keccak::v256();
    hasher.update(&pubkey.as_bytes()[1..]);
    hasher.finalize(&mut keccak_out);

    let mut address = [0u8; 20];
    address.copy_from_slice(&keccak_out[12..]);
    Ok(address)
}

fn obscured_value(value: &ArgValue) -> ArgValue {
    match value {
        ArgValue::Hex(bytes) => ArgValue::Hex(vec![0u8; bytes.len()]),
        ArgValue::I64(_) => ArgValue::I64(0),
    }
}

fn to_json_arg(value: &ArgValue) -> serde_json::Value {
    match value {
        ArgValue::Hex(bytes) => json!({ "hex": bytes_to_hex_prefixed(bytes) }),
        ArgValue::I64(v) => json!({ "i64": v }),
    }
}

fn main() -> Result<()> {
    let args = Args::parse();

    let _from_address = parse_hex_address(&args.from).map_err(anyhow::Error::msg)?;
    let _nonce = args.nonce;

    let policy_file = File::open(&args.policy_file)
        .with_context(|| format!("failed to open {}", args.policy_file.display()))?;
    let reader = BufReader::new(policy_file);
    let mut policy: Vec<PolicyLine> = serde_json::from_reader(reader)
        .with_context(|| format!("invalid JSON in {}", args.policy_file.display()))?;
    if policy.is_empty() {
        bail!("policy file is empty");
    }
    policy.sort_by_key(|rule| rule.id);

    let groups = parse_address_book(&args.groups_file)?;
    let allowlists = parse_address_book(&args.allowlists_file)?;

    let mut flattened_policy: Vec<FlattenedRule> = Vec::with_capacity(policy.len());
    for rule in &policy {
        flattened_policy.push(flatten_rule(rule, &groups, &allowlists)?);
    }

    let selected_index = flattened_policy
        .iter()
        .position(|rule| rule.id == i64::from(args.rule_id))
        .with_context(|| format!("rule id {} not found in policy", args.rule_id))?;
    let selected = flattened_policy[selected_index].clone();

    let mut leaves = flattened_policy
        .iter()
        .map(|rule| rule.leaf_hash)
        .collect::<Vec<[u8; 32]>>();
    let target_len = leaves.len().next_power_of_two();
    if target_len > leaves.len() {
        let last = *leaves.last().expect("non-empty leaves");
        leaves.extend(std::iter::repeat(last).take(target_len - leaves.len()));
    }

    let (policy_root, siblings) = merkle_root_and_path(&leaves, selected_index)?;
    let mut siblings_bytes = Vec::with_capacity(siblings.len() * 32);
    for sibling in &siblings {
        siblings_bytes.extend_from_slice(sibling);
    }

    let action_to = parse_hex_address(&args.to).map_err(anyhow::Error::msg)?;
    let action_value =
        i64::try_from(args.value).context("value exceeds i64::MAX for Ligero host input")?;
    let action_data = parse_hex_bytes(&args.data).map_err(anyhow::Error::msg)?;

    let mut action_signers = Vec::with_capacity(args.private_keys.len());
    for key in &args.private_keys {
        action_signers.push(private_key_to_address(key)?);
    }
    let action_signers_bytes = flatten_addresses(&action_signers);

    let destination_list_bytes = flatten_addresses(&selected.destination_list);
    let signer_list_bytes = flatten_addresses(&selected.signer_list);

    let prove_args = vec![
        ArgValue::Hex(policy_root.to_vec()),                            // 1
        ArgValue::Hex(selected.leaf_hash.to_vec()),                     // 2
        ArgValue::I64(selected_index as i64),                           // 3
        ArgValue::Hex(siblings_bytes),                                  // 4
        ArgValue::I64(siblings.len() as i64),                           // 5
        ArgValue::I64(selected.id),                                     // 6
        ArgValue::I64(selected.tx_type),                                // 7
        ArgValue::I64(selected.destination_mode),                       // 8
        ArgValue::Hex(selected.destination_exact.to_vec()),             // 9
        ArgValue::Hex(selected.destination_list_hash.to_vec()),         // 10
        ArgValue::I64(selected.signer_mode),                            // 11
        ArgValue::Hex(selected.signer_exact.to_vec()),                  // 12
        ArgValue::Hex(selected.signer_list_hash.to_vec()),              // 13
        ArgValue::I64(selected.signer_threshold),                       // 14
        ArgValue::I64(selected.asset_mode),                             // 15
        ArgValue::Hex(selected.asset_exact.to_vec()),                   // 16
        ArgValue::I64(selected.amount_max),                             // 17
        ArgValue::I64(selected.has_selector),                           // 18
        ArgValue::Hex(selected.selector.to_vec()),                      // 19
        ArgValue::Hex(destination_list_bytes),                          // 20
        ArgValue::I64(selected.destination_list.len() as i64),          // 21
        ArgValue::Hex(signer_list_bytes),                               // 22
        ArgValue::I64(selected.signer_list.len() as i64),               // 23
        ArgValue::Hex(action_to.to_vec()),                              // 24
        ArgValue::I64(action_value),                                    // 25
        ArgValue::Hex(action_data),                                     // 26
        ArgValue::Hex(action_signers_bytes),                            // 27
        ArgValue::I64(action_signers.len() as i64),                     // 28
    ];

    for idx in &args.private_indices {
        if *idx == 0 || *idx > prove_args.len() {
            bail!(
                "private index {} out of range; expected [1, {}]",
                idx,
                prove_args.len()
            );
        }
    }

    let mut verify_args = prove_args.clone();
    if args.obscure_private {
        for idx in &args.private_indices {
            verify_args[*idx - 1] = obscured_value(&verify_args[*idx - 1]);
        }
    }

    let prover_json = json!({
        "program": args.program,
        "shader-path": args.shader_path,
        "packing": args.packing,
        "private-indices": args.private_indices,
        "args": prove_args.iter().map(to_json_arg).collect::<Vec<_>>(),
    });
    let verifier_json = json!({
        "program": args.program,
        "shader-path": args.shader_path,
        "packing": args.packing,
        "private-indices": args.private_indices,
        "args": verify_args.iter().map(to_json_arg).collect::<Vec<_>>(),
    });

    std::fs::write(
        &args.prover_out,
        serde_json::to_string_pretty(&prover_json).context("failed to encode prover JSON")?,
    )
    .with_context(|| format!("failed to write {}", args.prover_out.display()))?;
    std::fs::write(
        &args.verifier_out,
        serde_json::to_string_pretty(&verifier_json).context("failed to encode verifier JSON")?,
    )
    .with_context(|| format!("failed to write {}", args.verifier_out.display()))?;

    println!("Wrote prover input JSON to {}", args.prover_out.display());
    println!("Wrote verifier input JSON to {}", args.verifier_out.display());
    println!("Policy root: {}", bytes_to_hex_prefixed(&policy_root));
    println!("Selected rule leaf: {}", bytes_to_hex_prefixed(&selected.leaf_hash));

    Ok(())
}
