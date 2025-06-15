// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IRisc0Verifier {
    /// @notice returns true if proof is valid and the single public output
    ///         (commitment) equals the supplied `expectedCommit`
    function verify(
        bytes calldata proof,
        bytes32 expectedCommit
    ) external view returns (bool);
}

contract ZKGuardWrapper {
    IRisc0Verifier public immutable verifier;

    /// simple replay-protection
    mapping(address => mapping(uint64 => bool)) public used;

    constructor(address _verifier) {
        verifier = IRisc0Verifier(_verifier);
    }

    /// @notice Verify proof & forward arbitrary call
    /// @dev    packet = abi.encode(target,value,data,commitment,nonce,proof)
    function verifyAndForward(bytes calldata packet) external payable {
        (
            address target,
            uint256 value,
            bytes calldata innerData,
            bytes32 commitment,
            uint64 nonce,
            bytes calldata proof
        ) = abi.decode(
                packet,
                (address, uint256, bytes, bytes32, uint64, bytes)
            );

        // 1. prevent replay for (sender,nonce)
        require(!used[msg.sender][nonce], "nonce-used");
        used[msg.sender][nonce] = true;

        // 2. ETH invariance
        require(value == msg.value, "value-mismatch");

        // 3. re-compute commitment on-chain for integrity
        bytes32 local = keccak256(
            abi.encodePacked(msg.sender, target, value, innerData, nonce)
        );
        require(local == commitment, "bad-commitment");

        // 4. verify zero-knowledge proof (costs ~60k–150k gas for Groth16)
        require(verifier.verify(proof, commitment), "invalid-proof");

        // 5. forward the original intent
        (bool ok, bytes memory ret) = target.call{value: value}(innerData);
        require(ok, "target-call-failed");

        // 6. bubble return data (or emit event if you prefer)
        assembly {
            return(add(ret, 32), mload(ret))
        }
    }
}
