// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

interface IVectorX {
    /// @notice Emits event with the inputs of a header range request.
    /// @param trustedBlock The block height of the trusted block.
    /// @param trustedHeader The header hash of the trusted block.
    /// @param authoritySetId The authority set id of trusted block + 1.
    /// @param authoritySetHash The authority set hash of trusted block + 1.
    /// @param targetBlock The block height of the target block.
    event HeaderRangeRequested(
        uint32 trustedBlock,
        bytes32 trustedHeader,
        uint64 authoritySetId,
        bytes32 authoritySetHash,
        uint32 targetBlock
    );

    /// @notice Emits event with the inputs of a rotate request.
    /// @param currentAuthoritySetId The authority set id of the current authority set.
    /// @param currentAuthoritySetHash The authority set hash of the current authority set.
    /// @param epochEndBlock The height of the epoch end block.
    event RotateRequested(
        uint64 currentAuthoritySetId,
        bytes32 currentAuthoritySetHash,
        uint64 epochEndBlock
    );

    /// @notice Emitted when the light client's head is updated.
    event HeadUpdate(uint32 blockNumber, bytes32 headerHash);

    /// @notice Emitted when data + state commitment for range (startBlock, endBlock] are stored.
    event HeaderRangeCommitmentStored(
        uint32 startBlock,
        uint32 endBlock,
        bytes32 dataCommitment,
        bytes32 stateCommitment
    );

    /// @notice Emitted when a new authority set is stored.
    event AuthoritySetStored(
        uint64 authoritySetId,
        bytes32 authoritySetHash,
        uint64 epochEndBlock
    );
}
