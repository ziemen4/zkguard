"""Canonical off-circuit policy commitments for the Noir verifier.

The tree preserves policy.json array order and pads to the next power of two
with zero field elements. Siblings are ordered from the leaf toward the root.
"""

from dataclasses import dataclass

from poseidon2_constants import INTERNAL_MATRIX_DIAGONAL, ROUND_CONSTANTS


FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617
MAX_MERKLE_DEPTH = 8


def _external_matrix(state: list[int]) -> list[int]:
    a, b, c, d = state
    t0 = a + b
    t1 = c + d
    t2 = 2 * b + t1
    t3 = 2 * d + t0
    t4 = 4 * t1 + t3
    t5 = 4 * t0 + t2
    return [
        (t3 + t5) % FIELD_MODULUS,
        t5 % FIELD_MODULUS,
        (t2 + t4) % FIELD_MODULUS,
        t4 % FIELD_MODULUS,
    ]


def _permutation(state: list[int]) -> list[int]:
    state = _external_matrix(state)
    for round_index in range(4):
        state = [
            pow((value + constant) % FIELD_MODULUS, 5, FIELD_MODULUS)
            for value, constant in zip(state, ROUND_CONSTANTS[round_index])
        ]
        state = _external_matrix(state)

    for round_index in range(4, 60):
        state[0] = pow(
            (state[0] + ROUND_CONSTANTS[round_index][0]) % FIELD_MODULUS,
            5,
            FIELD_MODULUS,
        )
        total = sum(state) % FIELD_MODULUS
        state = [
            (value * diagonal + total) % FIELD_MODULUS
            for value, diagonal in zip(state, INTERNAL_MATRIX_DIAGONAL)
        ]

    for round_index in range(60, 64):
        state = [
            pow((value + constant) % FIELD_MODULUS, 5, FIELD_MODULUS)
            for value, constant in zip(state, ROUND_CONSTANTS[round_index])
        ]
        state = _external_matrix(state)
    return state


def poseidon2_hash(values: list[int]) -> int:
    """Match Poseidon2::hash(values, len(values)) in Noir poseidon2 v0.2.6."""
    state = [0, 0, 0, len(values) << 64]
    cache: list[int] = []
    for value in values:
        if not 0 <= value < FIELD_MODULUS:
            raise ValueError("Poseidon input is outside the BN254 scalar field")
        if len(cache) == 3:
            for i, cached in enumerate(cache):
                state[i] = (state[i] + cached) % FIELD_MODULUS
            state = _permutation(state)
            cache = []
        cache.append(value)

    cache.extend([0] * (3 - len(cache)))
    for i, cached in enumerate(cache):
        state[i] = (state[i] + cached) % FIELD_MODULUS
    return _permutation(state)[0]


def _bytes_to_field(value: bytes) -> int:
    return int.from_bytes(value, "big") % FIELD_MODULUS


def _address_to_field(value: bytes) -> int:
    if len(value) != 20:
        raise ValueError("policy address must be 20 bytes")
    return int.from_bytes(value, "big")


def hash_policy_rule(rule: dict) -> int:
    """Hash the canonical semantic fields used by hash_policy_leaf in main.nr."""
    destination = rule["destination"]
    signer = rule["signer"]
    asset = rule["asset"]
    destination_name = (
        _bytes_to_field(destination["name_hash_bytes"])
        if destination["kind"] in (1, 2)
        else 0
    )
    destination_address = (
        _address_to_field(destination["address"])
        if destination["kind"] == 3
        else 0
    )
    signer_address = _address_to_field(signer["address"]) if signer["kind"] == 1 else 0
    signer_group = (
        _bytes_to_field(signer["group_name_hash_bytes"])
        if signer["kind"] in (2, 3)
        else 0
    )
    signer_threshold = signer["threshold"] if signer["kind"] == 3 else 0
    asset_address = _address_to_field(asset["address"]) if asset["kind"] == 1 else 0
    amount_max = rule["amount_max"] if rule["has_amount_max"] else 0
    selector = (
        int.from_bytes(rule["function_selector"], "big")
        if rule["has_function_selector"]
        else 0
    )
    return poseidon2_hash(
        [
            rule["id"],
            rule["tx_type"],
            destination["kind"],
            destination_name,
            destination_address,
            signer["kind"],
            signer_address,
            signer_group,
            signer_threshold,
            asset["kind"],
            asset_address,
            int(rule["has_amount_max"]),
            amount_max,
            int(rule["has_function_selector"]),
            selector,
        ]
    )


@dataclass(frozen=True)
class PolicyMerklePath:
    root: int
    leaf_index: int
    depth: int
    siblings: tuple[int, ...]


def build_policy_merkle_path(rules: list[dict], selected_index: int) -> PolicyMerklePath:
    """Build the root and inclusion path for a rule in canonical policy order."""
    if not rules:
        raise ValueError("policy must contain at least one rule")
    if len(rules) > 1 << MAX_MERKLE_DEPTH:
        raise ValueError("policy exceeds the circuit's 256-rule limit")
    if not 0 <= selected_index < len(rules):
        raise IndexError("selected policy rule is outside the policy")
    ids = [rule["id"] for rule in rules]
    if len(ids) != len(set(ids)):
        raise ValueError("policy rule IDs must be unique")

    leaf_count = 1 << (len(rules) - 1).bit_length()
    level = [hash_policy_rule(rule) for rule in rules] + [0] * (leaf_count - len(rules))
    index = selected_index
    siblings: list[int] = []
    while len(level) > 1:
        siblings.append(level[index ^ 1])
        level = [poseidon2_hash(level[i : i + 2]) for i in range(0, len(level), 2)]
        index //= 2
    return PolicyMerklePath(level[0], selected_index, len(siblings), tuple(siblings))


def verify_policy_merkle_path(leaf: int, path: PolicyMerklePath) -> bool:
    value = leaf
    index = path.leaf_index
    for sibling in path.siblings:
        value = (
            poseidon2_hash([value, sibling])
            if index % 2 == 0
            else poseidon2_hash([sibling, value])
        )
        index //= 2
    return index == 0 and value == path.root
