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

    /// @notice Outputs of a header range proof.
    /// @param trustedBlock The block height of the trusted block.
    /// @param targetBlock The block height of the target block.
    /// @param targetHeaderHash The header hash of the target block.
    /// @param dataRootCommitment The data root commitment of the range (trustedBlock, targetBlock].
    /// @param stateRootCommitment The state root commitment of the range (trustedBlock, targetBlock].
    event HeaderRangeFulfilled(
        uint32 trustedBlock,
        uint32 targetBlock,
        bytes32 targetHeaderHash,
        bytes32 dataRootCommitment,
        bytes32 stateRootCommitment
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

    /// @notice Outputs of a rotate proof.
    /// @param newAuthoritySetId The authority set id of the new authority set.
    /// @param newAuthoritySetHash The authority set hash of the new authority set.
    /// @param epochEndBlock The height of the epoch end block.
    event RotateFulfilled(
        uint64 newAuthoritySetId,
        bytes32 newAuthoritySetHash,
        uint64 epochEndBlock
    );
}
