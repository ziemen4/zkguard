use ligetron::{assert_one, get_args};

const TRANSFER_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];

#[derive(Clone, Copy)]
struct ClassifiedAction {
    tx_type: i64,
    destination: [u8; 20],
    asset: [u8; 20],
    amount: u128,
}

fn as_fixed<const N: usize>(bytes: &[u8]) -> Option<[u8; N]> {
    if bytes.len() != N {
        return None;
    }
    let mut out = [0u8; N];
    out.copy_from_slice(bytes);
    Some(out)
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

fn parse_address_list(bytes: &[u8], count: i64) -> Option<Vec<[u8; 20]>> {
    if count < 0 {
        return None;
    }
    let count = count as usize;
    if bytes.len() != count * 20 {
        return None;
    }

    let mut list = Vec::with_capacity(count);
    let mut i = 0usize;
    while i < count {
        let start = i * 20;
        let end = start + 20;
        let mut addr = [0u8; 20];
        addr.copy_from_slice(&bytes[start..end]);
        list.push(addr);
        i += 1;
    }
    Some(list)
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

#[allow(clippy::too_many_arguments)]
fn hash_rule(
    rule_id: i64,
    tx_type: i64,
    destination_mode: i64,
    destination_exact: &[u8; 20],
    destination_list_hash: &[u8; 32],
    signer_mode: i64,
    signer_exact: &[u8; 20],
    signer_list_hash: &[u8; 32],
    signer_threshold: i64,
    asset_mode: i64,
    asset_exact: &[u8; 20],
    amount_max: i64,
    has_selector: i64,
    selector: &[u8; 4],
) -> [u8; 32] {
    let mut blob = Vec::with_capacity(1 + 8 * 13 + 20 * 3 + 32 * 2 + 4);
    blob.push(0x52);
    blob.extend_from_slice(&rule_id.to_le_bytes());
    blob.extend_from_slice(&tx_type.to_le_bytes());
    blob.extend_from_slice(&destination_mode.to_le_bytes());
    blob.extend_from_slice(destination_exact);
    blob.extend_from_slice(destination_list_hash);
    blob.extend_from_slice(&signer_mode.to_le_bytes());
    blob.extend_from_slice(signer_exact);
    blob.extend_from_slice(signer_list_hash);
    blob.extend_from_slice(&signer_threshold.to_le_bytes());
    blob.extend_from_slice(&asset_mode.to_le_bytes());
    blob.extend_from_slice(asset_exact);
    blob.extend_from_slice(&amount_max.to_le_bytes());
    blob.extend_from_slice(&has_selector.to_le_bytes());
    blob.extend_from_slice(selector);
    mix_hash(&blob)
}

fn parse_erc20_transfer(data: &[u8]) -> Option<([u8; 20], u128)> {
    if data.len() < 4 + 32 + 32 {
        return None;
    }
    if data[..4] != TRANSFER_SELECTOR {
        return None;
    }

    let mut destination = [0u8; 20];
    destination.copy_from_slice(&data[4 + 12..4 + 32]);

    let mut amount_bytes = [0u8; 16];
    amount_bytes.copy_from_slice(&data[4 + 32 + 16..4 + 64]);
    let amount = u128::from_be_bytes(amount_bytes);
    Some((destination, amount))
}

fn classify_action(action_to: &[u8; 20], action_value: i64, action_data: &[u8]) -> Option<ClassifiedAction> {
    if action_value < 0 {
        return None;
    }

    let native_value = action_value as u128;
    if action_value > 0 {
        if action_data.is_empty() {
            return Some(ClassifiedAction {
                tx_type: 0,
                destination: *action_to,
                asset: [0u8; 20],
                amount: native_value,
            });
        }

        if let Some((destination, amount)) = parse_erc20_transfer(action_data) {
            return Some(ClassifiedAction {
                tx_type: 0,
                destination,
                asset: *action_to,
                amount,
            });
        }

        return None;
    }

    if let Some((destination, amount)) = parse_erc20_transfer(action_data) {
        return Some(ClassifiedAction {
            tx_type: 0,
            destination,
            asset: *action_to,
            amount,
        });
    }

    Some(ClassifiedAction {
        tx_type: 1,
        destination: *action_to,
        asset: [0u8; 20],
        amount: 0,
    })
}

fn address_in_list(address: &[u8; 20], list: &[[u8; 20]]) -> bool {
    let mut i = 0usize;
    while i < list.len() {
        if &list[i] == address {
            return true;
        }
        i += 1;
    }
    false
}

fn count_unique_signers_in_list(signers: &[[u8; 20]], allowed: &[[u8; 20]]) -> usize {
    let mut unique: Vec<[u8; 20]> = Vec::new();
    let mut i = 0usize;
    while i < signers.len() {
        let signer = signers[i];
        if address_in_list(&signer, allowed) {
            let mut seen = false;
            let mut j = 0usize;
            while j < unique.len() {
                if unique[j] == signer {
                    seen = true;
                    break;
                }
                j += 1;
            }
            if !seen {
                unique.push(signer);
            }
        }
        i += 1;
    }
    unique.len()
}

fn verify_merkle_membership(
    root: &[u8; 32],
    leaf: &[u8; 32],
    leaf_index: i64,
    siblings: &[[u8; 32]],
) -> bool {
    if leaf_index < 0 {
        return false;
    }

    let mut idx = leaf_index as usize;
    let mut current = *leaf;
    let mut i = 0usize;
    while i < siblings.len() {
        current = if idx % 2 == 0 {
            hash_pair(&current, &siblings[i])
        } else {
            hash_pair(&siblings[i], &current)
        };
        idx /= 2;
        i += 1;
    }

    current == *root
}

fn main() {
    let args = get_args();
    if args.len() < 29 {
        assert_one(false);
        return;
    }

    let policy_root = match as_fixed::<32>(args.get_as_bytes(1)) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };
    let leaf_hash = match as_fixed::<32>(args.get_as_bytes(2)) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };
    let leaf_index = args.get_as_int(3);
    let sibling_bytes = args.get_as_bytes(4);
    let sibling_count = args.get_as_int(5);
    if sibling_count < 0 || sibling_bytes.len() != (sibling_count as usize) * 32 {
        assert_one(false);
        return;
    }
    let mut siblings = Vec::with_capacity(sibling_count as usize);
    let mut sib_i = 0usize;
    while sib_i < sibling_count as usize {
        let start = sib_i * 32;
        let end = start + 32;
        let mut sibling = [0u8; 32];
        sibling.copy_from_slice(&sibling_bytes[start..end]);
        siblings.push(sibling);
        sib_i += 1;
    }

    let rule_id = args.get_as_int(6);
    let rule_tx_type = args.get_as_int(7);
    let destination_mode = args.get_as_int(8);
    let destination_exact = match as_fixed::<20>(args.get_as_bytes(9)) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };
    let destination_list_hash = match as_fixed::<32>(args.get_as_bytes(10)) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };
    let signer_mode = args.get_as_int(11);
    let signer_exact = match as_fixed::<20>(args.get_as_bytes(12)) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };
    let signer_list_hash = match as_fixed::<32>(args.get_as_bytes(13)) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };
    let signer_threshold = args.get_as_int(14);
    let asset_mode = args.get_as_int(15);
    let asset_exact = match as_fixed::<20>(args.get_as_bytes(16)) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };
    let amount_max = args.get_as_int(17);
    let has_selector = args.get_as_int(18);
    let selector = match as_fixed::<4>(args.get_as_bytes(19)) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };

    let destination_list =
        match parse_address_list(args.get_as_bytes(20), args.get_as_int(21)) {
            Some(v) => v,
            None => {
                assert_one(false);
                return;
            }
        };
    let signer_list = match parse_address_list(args.get_as_bytes(22), args.get_as_int(23)) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };

    let action_to = match as_fixed::<20>(args.get_as_bytes(24)) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };
    let action_value = args.get_as_int(25);
    let action_data = args.get_as_bytes(26);
    let action_signers = match parse_address_list(args.get_as_bytes(27), args.get_as_int(28)) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };

    let recomputed_destination_hash = hash_address_list(&destination_list);
    let recomputed_signer_hash = hash_address_list(&signer_list);
    let recomputed_rule_hash = hash_rule(
        rule_id,
        rule_tx_type,
        destination_mode,
        &destination_exact,
        &destination_list_hash,
        signer_mode,
        &signer_exact,
        &signer_list_hash,
        signer_threshold,
        asset_mode,
        &asset_exact,
        amount_max,
        has_selector,
        &selector,
    );

    let action = match classify_action(&action_to, action_value, action_data) {
        Some(v) => v,
        None => {
            assert_one(false);
            return;
        }
    };

    let mut is_valid = true;

    is_valid = is_valid && leaf_hash == recomputed_rule_hash;
    is_valid = is_valid && verify_merkle_membership(&policy_root, &leaf_hash, leaf_index, &siblings);

    if destination_mode == 2 {
        is_valid = is_valid && destination_list_hash == recomputed_destination_hash;
    }
    if signer_mode == 2 || signer_mode == 3 {
        is_valid = is_valid && signer_list_hash == recomputed_signer_hash;
    }

    is_valid = is_valid
        && match destination_mode {
            0 => true,
            1 => action.destination == destination_exact,
            2 => address_in_list(&action.destination, &destination_list),
            _ => false,
        };

    is_valid = is_valid
        && match signer_mode {
            0 => !action_signers.is_empty(),
            1 => action_signers.len() == 1 && action_signers[0] == signer_exact,
            2 => action_signers.len() == 1 && address_in_list(&action_signers[0], &signer_list),
            3 => {
                signer_threshold > 0
                    && count_unique_signers_in_list(&action_signers, &signer_list)
                        >= signer_threshold as usize
            }
            _ => false,
        };

    is_valid = is_valid
        && match asset_mode {
            0 => true,
            1 => action.asset == asset_exact,
            _ => false,
        };

    is_valid = is_valid && action.tx_type == rule_tx_type;

    if action.tx_type == 0 {
        if amount_max >= 0 {
            is_valid = is_valid && action.amount <= amount_max as u128;
        }
    } else {
        // In zkguard, ContractCall rules cannot constrain asset with Exact.
        is_valid = is_valid && asset_mode == 0;
        if has_selector == 1 {
            is_valid = is_valid && action_data.len() >= 4 && action_data[..4] == selector;
        } else {
            is_valid = is_valid && has_selector == 0;
        }
    }

    assert_one(is_valid);
}
