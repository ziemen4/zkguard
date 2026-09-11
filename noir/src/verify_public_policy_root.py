#!/usr/bin/env python3
"""Reject a Noir proof input file unless it is bound to a trusted policy root."""

import argparse
from pathlib import Path


FIELD_BYTES = 32
# With the current ABI, the public main argument comes first. PublicOutputs then
# contains call_hash[32] followed by policy_hash, placing it at field 33.
REGISTERED_ROOT_FIELD_INDEX = 0
POLICY_HASH_FIELD_INDEX = 33


def verify_public_policy_root(public_inputs: bytes, expected_root: int) -> None:
    if len(public_inputs) % FIELD_BYTES != 0:
        raise ValueError("public-input file is not a sequence of 32-byte fields")
    fields = [
        int.from_bytes(public_inputs[offset : offset + FIELD_BYTES], "big")
        for offset in range(0, len(public_inputs), FIELD_BYTES)
    ]
    if len(fields) <= POLICY_HASH_FIELD_INDEX:
        raise ValueError("public-input file is too short for the zkguard ABI")
    if fields[REGISTERED_ROOT_FIELD_INDEX] != expected_root:
        raise ValueError("proof uses an unregistered policy root")
    if fields[POLICY_HASH_FIELD_INDEX] != expected_root:
        raise ValueError("circuit policy_hash does not match the registered root")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("public_inputs", type=Path)
    parser.add_argument("--expected-policy-root", required=True, type=lambda value: int(value, 0))
    args = parser.parse_args()
    verify_public_policy_root(args.public_inputs.read_bytes(), args.expected_policy_root)
    print(f"Verified registered policy root: 0x{args.expected_policy_root:064x}")


if __name__ == "__main__":
    main()
