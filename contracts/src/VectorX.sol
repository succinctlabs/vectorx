// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IVectorX} from "./interfaces/IVectorX.sol";
import {TimelockedUpgradeable} from "@succinctx/upgrades/TimelockedUpgradeable.sol";
import {ISuccinctGateway} from "@succinctx/interfaces/ISuccinctGateway.sol";

/// @notice VectorX is a light client for Avail's consensus.
/// @dev The light client tracks both the state of Avail's Grandpa consensus and Vector, Avail's
///     data commitment solution.
contract VectorX is IVectorX, TimelockedUpgradeable {
    /// @notice Indicator of if the contract is frozen.
    bool public frozen;

    /// @notice The address of the gateway contract.
    address public gateway;

    /// @notice The latest block that has been committed.
    uint32 public latestBlock;

    /// @notice The function for requesting a header range.
    bytes32 public headerRangeFunctionId;

    /// @notice The function for requesting a rotate.
    bytes32 public rotateFunctionId;

    /// @notice Maps block height to the header hash of the block.
    mapping(uint32 => bytes32) public blockHeightToHeaderHash;

    /// @notice Maps authority set id to the authority set hash.
    mapping(uint64 => bytes32) public authoritySetIdToHash;

    /// @notice Maps block ranges to data commitments. Block ranges are stored as
    ///     keccak256(abi.encode(startBlock, endBlock)).
    mapping(bytes32 => bytes32) public dataRootCommitments;

    /// @notice Maps block ranges to state commitments. Block ranges are stored as
    ///     keccak256(abi.encode(startBlock, endBlock)).
    mapping(bytes32 => bytes32) public stateRootCommitments;

    struct InitParameters {
        address guardian;
        address gateway;
        uint32 height;
        bytes32 header;
        uint64 authoritySetId;
        bytes32 authoritySetHash;
        bytes32 headerRangeFunctionId;
        bytes32 rotateFunctionId;
    }

    function VERSION() external pure override returns (string memory) {
        return "0.1.2";
    }

    /// @dev Initializes the contract.
    /// @param _params The initialization parameters for the contract.
    function initialize(InitParameters calldata _params) external initializer {
        gateway = _params.gateway;

        blockHeightToHeaderHash[_params.height] = _params.header;
        authoritySetIdToHash[_params.authoritySetId] = _params.authoritySetHash;
        latestBlock = _params.height;

        rotateFunctionId = _params.rotateFunctionId;
        headerRangeFunctionId = _params.headerRangeFunctionId;

        __TimelockedUpgradeable_init(_params.guardian, _params.guardian);
    }

    /// @notice Update the freeze parameter.
    function updateFreeze(bool _freeze) external onlyGuardian {
        frozen = _freeze;
    }

    /// @notice Update the function IDs.
    function updateFunctionIds(
        bytes32 _headerRangeFunctionId,
        bytes32 _rotateFunctionId
    ) external onlyGuardian {
        headerRangeFunctionId = _headerRangeFunctionId;
        rotateFunctionId = _rotateFunctionId;
    }

    /// @notice Update the gateway address.
    function updateGateway(address _gateway) external onlyGuardian {
        gateway = _gateway;
    }

    /// @notice Update the genesis state of the light client.
    function updateGenesisState(
        uint32 _height,
        bytes32 _header,
        uint64 _authoritySetId,
        bytes32 _authoritySetHash
    ) external onlyGuardian {
        blockHeightToHeaderHash[_height] = _header;
        authoritySetIdToHash[_authoritySetId] = _authoritySetHash;
        latestBlock = _height;
    }

    /// @notice Force update the data & state commitments for a range of blocks.
    function updateBlockRangeData(
        uint32[] calldata _startBlocks,
        uint32[] calldata _endBlocks,
        bytes32[] calldata _headerHashes,
        bytes32[] calldata _dataRootCommitments,
        bytes32[] calldata _stateRootCommitments,
        uint64 _endAuthoritySetId,
        bytes32 _endAuthoritySetHash
    ) external onlyGuardian {
        assert(
            _startBlocks.length > 0 &&
                _startBlocks.length == _endBlocks.length &&
                _endBlocks.length == _headerHashes.length &&
                _headerHashes.length == _dataRootCommitments.length &&
                _dataRootCommitments.length == _stateRootCommitments.length
        );
        require(_startBlocks[0] == latestBlock);
        for (uint256 i = 0; i < _startBlocks.length; i++) {
            if (i < _startBlocks.length - 1) {
                require(_endBlocks[i] == _startBlocks[i + 1]);
            }
            bytes32 key = keccak256(abi.encode(_startBlocks[i], _endBlocks[i]));
            dataRootCommitments[key] = _dataRootCommitments[i];
            stateRootCommitments[key] = _stateRootCommitments[i];

            blockHeightToHeaderHash[_endBlocks[i]] = _headerHashes[i];

            emit HeadUpdate(_endBlocks[i], _headerHashes[i]);

            emit HeaderRangeCommitmentStored(
                _startBlocks[i],
                _endBlocks[i],
                _dataRootCommitments[i],
                _stateRootCommitments[i]
            );
        }
        authoritySetIdToHash[_endAuthoritySetId] = _endAuthoritySetHash;
        latestBlock = _endBlocks[_endBlocks.length - 1];
    }

    /// @notice Request a header update and data commitment from range (latestBlock, requestedBlock].
    /// @param _authoritySetId The authority set id of the header range (latestBlock, requestedBlock].
    /// @param _requestedBlock The block height of the requested block.
    /// @dev The trusted block and requested block must have the same authority id. If the target
    /// block is greater than the max batch size of the circuit, the proof will fail to generate.
    function requestHeaderRange(
        uint64 _authoritySetId,
        uint32 _requestedBlock
    ) external payable {
        bytes32 trustedHeader = blockHeightToHeaderHash[latestBlock];
        if (trustedHeader == bytes32(0)) {
            revert AuthoritySetNotFound();
        }
        // Note: In the case that the trusted block is an epoch end block, the authority set id will
        // be the authority set id of the next epoch.
        bytes32 authoritySetHash = authoritySetIdToHash[_authoritySetId];
        if (authoritySetHash == bytes32(0)) {
            revert AuthoritySetNotFound();
        }

        require(_requestedBlock > latestBlock);

        bytes memory input = abi.encodePacked(
            latestBlock,
            trustedHeader,
            _authoritySetId,
            authoritySetHash,
            _requestedBlock
        );

        bytes memory data = abi.encodeWithSelector(
            this.commitHeaderRange.selector,
            _authoritySetId,
            _requestedBlock
        );

        ISuccinctGateway(gateway).requestCall{value: msg.value}(
            headerRangeFunctionId,
            input,
            address(this),
            data,
            500000
        );

        emit HeaderRangeRequested(
            latestBlock,
            trustedHeader,
            _authoritySetId,
            authoritySetHash,
            _requestedBlock
        );
    }

    /// @notice Add target header hash, and data + state commitments for (latestBlock, targetBlock].
    /// @param _authoritySetId The authority set id of the header range (latestBlock, targetBlock].
    /// @param _targetBlock The block height of the target block.
    /// @dev The trusted block and requested block must have the same authority set id. If the target
    /// block is greater than the max batch size of the circuit, the proof will fail to generate.
    function commitHeaderRange(
        uint64 _authoritySetId,
        uint32 _targetBlock
    ) external {
        if (frozen) {
            revert ContractFrozen();
        }

        bytes32 trustedHeader = blockHeightToHeaderHash[latestBlock];
        if (trustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }
        bytes32 authoritySetHash = authoritySetIdToHash[_authoritySetId];
        if (authoritySetHash == bytes32(0)) {
            revert AuthoritySetNotFound();
        }

        require(_targetBlock > latestBlock);

        bytes memory input = abi.encodePacked(
            latestBlock,
            trustedHeader,
            _authoritySetId,
            authoritySetHash,
            _targetBlock
        );

        bytes memory output = ISuccinctGateway(gateway).verifiedCall(
            headerRangeFunctionId,
            input
        );

        (
            bytes32 targetHeaderHash,
            bytes32 stateRootCommitment,
            bytes32 dataRootCommitment
        ) = abi.decode(output, (bytes32, bytes32, bytes32));

        blockHeightToHeaderHash[_targetBlock] = targetHeaderHash;

        // Store the data and state commitments for the range (latestBlock, targetBlock].
        bytes32 key = keccak256(abi.encode(latestBlock, _targetBlock));
        dataRootCommitments[key] = dataRootCommitment;
        stateRootCommitments[key] = stateRootCommitment;

        emit HeadUpdate(_targetBlock, targetHeaderHash);

        emit HeaderRangeCommitmentStored(
            latestBlock,
            _targetBlock,
            dataRootCommitment,
            stateRootCommitment
        );

        // Update latest block.
        latestBlock = _targetBlock;
    }

    /// @notice Requests a rotate to the next authority set.
    /// @param _currentAuthoritySetId The authority set id of the current authority set.
    function requestRotate(uint64 _currentAuthoritySetId) external payable {
        bytes32 currentAuthoritySetHash = authoritySetIdToHash[
            _currentAuthoritySetId
        ];
        if (currentAuthoritySetHash == bytes32(0)) {
            revert AuthoritySetNotFound();
        }

        bytes32 nextAuthoritySetHash = authoritySetIdToHash[
            _currentAuthoritySetId + 1
        ];
        if (nextAuthoritySetHash != bytes32(0)) {
            revert NextAuthoritySetExists();
        }

        bytes memory input = abi.encodePacked(
            _currentAuthoritySetId,
            currentAuthoritySetHash
        );

        bytes memory data = abi.encodeWithSelector(
            this.rotate.selector,
            _currentAuthoritySetId
        );

        ISuccinctGateway(gateway).requestCall{value: msg.value}(
            rotateFunctionId,
            input,
            address(this),
            data,
            500000
        );

        emit RotateRequested(_currentAuthoritySetId, currentAuthoritySetHash);
    }

    /// @notice Adds the authority set hash for the next authority set id.
    /// @param _currentAuthoritySetId The authority set id of the current authority set.
    function rotate(uint64 _currentAuthoritySetId) external {
        if (frozen) {
            revert ContractFrozen();
        }

        bytes32 currentAuthoritySetHash = authoritySetIdToHash[
            _currentAuthoritySetId
        ];
        // Note: Occurs if requesting a new authority set id that is not the next authority set id.
        if (currentAuthoritySetHash == bytes32(0)) {
            revert AuthoritySetNotFound();
        }

        bytes32 nextAuthoritySetHash = authoritySetIdToHash[
            _currentAuthoritySetId + 1
        ];
        if (nextAuthoritySetHash != bytes32(0)) {
            revert NextAuthoritySetExists();
        }

        bytes memory input = abi.encodePacked(
            _currentAuthoritySetId,
            currentAuthoritySetHash
        );

        bytes memory output = ISuccinctGateway(gateway).verifiedCall(
            rotateFunctionId,
            input
        );

        bytes32 newAuthoritySetHash = abi.decode(output, (bytes32));

        // Store the authority set hash for the next authority set id.
        authoritySetIdToHash[_currentAuthoritySetId + 1] = newAuthoritySetHash;

        emit AuthoritySetStored(
            _currentAuthoritySetId + 1,
            newAuthoritySetHash
        );
    }
}
