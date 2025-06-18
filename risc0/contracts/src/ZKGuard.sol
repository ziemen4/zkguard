// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IRiscZeroVerifier} from "../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

/// @notice Interface for the ImageID contract.
interface IImageID {
    function ZKPOEX_GUEST_ID() external view returns (bytes32);
}

contract ZKGuardWrapper {
    /// @notice Image ID of the only zkVM binary to accept verification from.
    bytes32 public imageId;

    IRiscZeroVerifier public immutable verifier;

    /// simple replay-protection
    mapping(address => mapping(uint64 => bool)) public used;

    bytes32 public policy_hash;
    bytes32 public groups_hash;
    bytes32 public allow_hash;

    constructor(
        address _verifier,
        bytes32 _policy_hash,
        bytes32 _groups_hash,
        bytes32 _allow_hash
    ) {
        verifier = IRiscZeroVerifier(_verifier);
        policy_hash = _policy_hash;
        groups_hash = _groups_hash;
        allow_hash = _allow_hash;
    }

    /// @notice Verify proof & forward arbitrary call
    /// @dev    packet = abi.encode(target,value,data,commitment,nonce,proof)
    function verifyAndForward(
        bytes calldata userAction,
        bytes calldata seal,
        bytes calldata journal // What the user wants to delegate to the target
    ) public payable {
        // Verify if ZK proof is valid
        verifier.verify(seal, imageId, sha256(journal));

        // Get public values from the journal
        (
            bytes32 claimed_action_hash,
            bytes32 claimed_policy_hash,
            bytes32 claimed_groups_hash,
            bytes32 claimed_allow_hash
        ) = abi.decode(journal, (bytes32, bytes32, bytes32, bytes32));

        // Verify that userAction (the action to be performed) matches the claimed action hash
        require(
            claimed_action_hash == keccak256(userAction),
            "action-hash-mismatch"
        );

        // Verify that the claimed policy, groups, and allow hashes match the contract's state
        require(claimed_policy_hash == policy_hash, "policy-hash-mismatch");
        require(claimed_groups_hash == groups_hash, "groups-hash-mismatch");
        require(claimed_allow_hash == allow_hash, "allow-hash-mismatch");

        // Decode the user action
        (
            address to,
            uint256 value,
            bytes memory data,
            address signer,
            bytes memory signature
        ) = abi.decode(userAction, (address, uint256, bytes, address, bytes));

        // Forward the original user action to the target
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        require(ok, "target-call-failed");

        // Bubble return data
        assembly {
            return(add(ret, 32), mload(ret))
        }
    }
}
