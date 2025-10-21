// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

import {IRiscZeroVerifier} from "../lib/risc0-ethereum/contracts/src/IRiscZeroVerifier.sol";

/// @notice Interface for the ImageID contract.
interface IImageID {
    function ZKPOEX_GUEST_ID() external view returns (bytes32);
}

contract ZKGuardWrapper {
    /// Immutable verifier + imageId (pinned at construction time).
    /// @notice Image ID of the only zkVM binary to accept verification from.
    bytes32 public imageId;
    IRiscZeroVerifier public immutable VERIFIER;
    /// Policy root commitments pinned in the module.
    bytes32 public immutable POLICY_HASH;
    bytes32 public immutable GROUPS_HASH;
    bytes32 public immutable ALLOW_HASH;

    /// simple replay-protection
    mapping(address => mapping(uint256 => bool)) public nonce;

    bytes32 public policy_hash;
    bytes32 public groups_hash;
    bytes32 public allow_hash;

    constructor(
        address _verifier,
        bytes32 _policy_hash,
        bytes32 _groups_hash,
        bytes32 _allow_hash
    ) {
        VERIFIER = IRiscZeroVerifier(_verifier);
        POLICY_HASH = _policy_hash;
        GROUPS_HASH = _groups_hash;
        ALLOW_HASH = _allow_hash;
    }

    /// @notice Verify proof & forward arbitrary call
    /// @dev    packet = abi.encode(target,value,data,commitment,nonce,proof)
    function verifyAndForward(
        bytes calldata userAction,
        bytes calldata seal,
        bytes calldata journal // What the user wants to delegate to the target
    ) public payable {
        // (1) Verify RISC Zero proof; inherits all invariants enforced by the canonical verifier.
        bytes32 jdig = sha256(journal);
        VERIFIER.verify(seal, imageId, jdig);

        // (2) Decode journal claims + enforce against module state.
        (
            bytes32 claimedActionHash,
            bytes32 claimedPolicyHash,
            bytes32 claimedGroupsHash,
            bytes32 claimedAllowHash
        ) = abi.decode(journal, (bytes32, bytes32, bytes32, bytes32));

        require(claimedPolicyHash == POLICY_HASH, "policy-hash-mismatch");
        require(claimedGroupsHash == GROUPS_HASH, "groups-hash-mismatch");
        require(claimedAllowHash == ALLOW_HASH, "allow-hash-mismatch");

        // (3) Decode the user action.
        (address to, uint256 value, uint256 _nonce, bytes memory data) = abi
            .decode(userAction, (address, uint256, uint256, bytes));

        // (4) Bind to exact user action.
        bytes32 actionHash = keccak256(userAction);
        require(claimedActionHash == actionHash, "action-hash-mismatch");

        // (5) Simple replay-protection
        require(!nonce[msg.sender][_nonce], "nonce-reuse");

        // Forward the original user action to the target
        (bool ok, bytes memory ret) = to.call{value: value}(data);
        require(ok, "target-call-failed");

        // Bubble return data
        assembly {
            return(add(ret, 32), mload(ret))
        }
    }
}
