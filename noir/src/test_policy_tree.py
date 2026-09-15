#!/usr/bin/env python3
"""Regression vectors for the canonical off-circuit Poseidon2 policy tree."""

import copy
import json
import unittest
from pathlib import Path

from generate_shared_prover_toml import build_rule
from policy_tree import (
    _permutation,
    build_policy_merkle_path,
    hash_policy_rule,
    verify_policy_merkle_path,
)
from verify_public_policy_root import (
    POLICY_HASH_FIELD_INDEX,
    REGISTERED_ROOT_FIELD_INDEX,
    verify_public_policy_root,
)


SHARED_POLICY_ROOT = 0x100E811956318AECD68B8053366C1D32854E580B84C32DFE9FF175619198F10C


class PolicyTreeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        policy_path = Path(__file__).resolve().parents[2] / "shared" / "config" / "policy.json"
        with open(policy_path, encoding="utf-8") as policy_file:
            cls.rules = [build_rule(rule) for rule in json.load(policy_file)]

    def test_barretenberg_poseidon2_permutation_vector(self) -> None:
        self.assertEqual(
            _permutation([0, 1, 2, 3]),
            [
                0x01BD538C2EE014ED5141B29E9AE240BF8DB3FE5B9A38629A9647CF8D76C01737,
                0x239B62E7DB98AA3A2A8F6A0D2FA1709E7A35959AA6C7034814D9DAA90CBAC662,
                0x04CBB44C61D928ED06808456BF758CBF0C18D1E15A7B6DBC8245FA7515D5E3CB,
                0x2E11C5CFF2A22C64D01304B778D78F6998EFF1AB73163A35603F54794C30847A,
            ],
        )

    def test_shared_policy_golden_root_and_every_path(self) -> None:
        for index, rule in enumerate(self.rules):
            path = build_policy_merkle_path(self.rules, index)
            self.assertEqual(path.root, SHARED_POLICY_ROOT)
            self.assertEqual(path.depth, 3)
            self.assertTrue(verify_policy_merkle_path(hash_policy_rule(rule), path))

    def test_depth_one_and_two_left_right_paths(self) -> None:
        for count in (2, 4):
            for index, rule in enumerate(self.rules[:count]):
                path = build_policy_merkle_path(self.rules[:count], index)
                self.assertEqual(path.depth, count.bit_length() - 1)
                self.assertTrue(verify_policy_merkle_path(hash_policy_rule(rule), path))

    def test_wrong_sibling_and_index_are_rejected(self) -> None:
        path = build_policy_merkle_path(self.rules, 1)
        wrong_sibling = path.__class__(
            path.root,
            path.leaf_index,
            path.depth,
            (path.siblings[0] + 1,) + path.siblings[1:],
        )
        wrong_index = path.__class__(path.root, path.leaf_index ^ 1, path.depth, path.siblings)
        leaf = hash_policy_rule(self.rules[1])
        self.assertFalse(verify_policy_merkle_path(leaf, wrong_sibling))
        self.assertFalse(verify_policy_merkle_path(leaf, wrong_index))

    def test_rule_id_is_committed(self) -> None:
        path = build_policy_merkle_path(self.rules, 1)
        mutated = copy.deepcopy(self.rules[1])
        mutated["id"] += 100
        self.assertNotEqual(hash_policy_rule(mutated), hash_policy_rule(self.rules[1]))
        self.assertFalse(verify_policy_merkle_path(hash_policy_rule(mutated), path))

    def test_authorizer_rejects_consistent_untrusted_root(self) -> None:
        fields = [0] * (POLICY_HASH_FIELD_INDEX + 1)
        fields[REGISTERED_ROOT_FIELD_INDEX] = SHARED_POLICY_ROOT
        fields[POLICY_HASH_FIELD_INDEX] = SHARED_POLICY_ROOT
        encoded = b"".join(field.to_bytes(32, "big") for field in fields)
        verify_public_policy_root(encoded, SHARED_POLICY_ROOT)

        untrusted_root = SHARED_POLICY_ROOT + 1
        fields[REGISTERED_ROOT_FIELD_INDEX] = untrusted_root
        fields[POLICY_HASH_FIELD_INDEX] = untrusted_root
        attacker_inputs = b"".join(field.to_bytes(32, "big") for field in fields)
        with self.assertRaisesRegex(ValueError, "unregistered policy root"):
            verify_public_policy_root(attacker_inputs, SHARED_POLICY_ROOT)


if __name__ == "__main__":
    unittest.main()
