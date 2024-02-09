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

    /// @notice The maximum header range that can be requested.
    uint32 public constant MAX_HEADER_RANGE = 256;

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
        return "0.1.0";
    }

    /// @dev Initializes the contract.
    /// @param _params The initialization parameters for the contract.
    function initialize(InitParameters calldata _params) external initializer {
        __TimelockedUpgradeable_init(_params.guardian, _params.guardian);

        frozen = false;

        gateway = _params.gateway;

        blockHeightToHeaderHash[_params.height] = _params.header;
        authoritySetIdToHash[_params.authoritySetId] = _params.authoritySetHash;
        latestBlock = _params.height;

        rotateFunctionId = _params.rotateFunctionId;
        headerRangeFunctionId = _params.headerRangeFunctionId;
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
            _startBlocks.length == _endBlocks.length &&
                _endBlocks.length == _headerHashes.length &&
                _headerHashes.length == _dataRootCommitments.length &&
                _dataRootCommitments.length == _stateRootCommitments.length
        );

        for (uint256 i = 0; i < _startBlocks.length; i++) {
            assert(_startBlocks[i] == latestBlock);
            bytes32 key = keccak256(
                abi.encode(_startBlocks[i], _endBlocks[i])
            );
            dataRootCommitments[key] = _dataRootCommitments[i];
            stateRootCommitments[key] = _stateRootCommitments[i];

            blockHeightToHeaderHash[_endBlocks[i]] = _headerHashes[i];
            authoritySetIdToHash[_endAuthoritySetId] = _endAuthoritySetHash;
            latestBlock = _endBlocks[i];

            emit HeadUpdate(_endBlocks[i], _headerHashes[i]);

            emit HeaderRangeCommitmentStored(
                _startBlocks[i],
                _endBlocks[i],
                _dataRootCommitments[i],
                _stateRootCommitments[i]
            );
        }
    }

    /// @notice Request a header update and data commitment from range (trustedBlock, requestedBlock].
    /// @param _trustedBlock The block height of the trusted block.
    /// @param _authoritySetId The authority set id of the header range (trustedBlock, requestedBlock].
    /// @param _requestedBlock The block height of the requested block.
    /// @dev The trusted block and requested block must have the same authority id.
    function requestHeaderRange(
        uint32 _trustedBlock,
        uint64 _authoritySetId,
        uint32 _requestedBlock
    ) external payable {
        bytes32 trustedHeader = blockHeightToHeaderHash[_trustedBlock];
        if (trustedHeader == bytes32(0)) {
            revert AuthoritySetNotFound();
        }
        // Note: In the case that the trusted block is an epoch end block, the authority set id will
        // be the authority set id of the next epoch.
        bytes32 authoritySetHash = authoritySetIdToHash[_authoritySetId];
        if (authoritySetHash == bytes32(0)) {
            revert AuthoritySetNotFound();
        }

        require(_requestedBlock > _trustedBlock);
        require(_requestedBlock - _trustedBlock <= MAX_HEADER_RANGE);
        // Note: This is needed to prevent a long-range attack on the light client.
        require(_requestedBlock > latestBlock);

        bytes memory input = abi.encodePacked(
            _trustedBlock,
            trustedHeader,
            _authoritySetId,
            authoritySetHash,
            _requestedBlock
        );

        bytes memory data = abi.encodeWithSelector(
            this.commitHeaderRange.selector,
            _trustedBlock,
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
            _trustedBlock,
            trustedHeader,
            _authoritySetId,
            authoritySetHash,
            _requestedBlock
        );
    }

    /// @notice Add target header hash, and data + state commitments for (trustedBlock, targetBlock].
    /// @param _trustedBlock The block height of the trusted block.
    /// @param _authoritySetId The authority set id of the header range (trustedBlock, targetBlock].
    /// @param _targetBlock The block height of the target block.
    /// @dev The trusted block and requested block must have the same authority set id.
    function commitHeaderRange(
        uint32 _trustedBlock,
        uint64 _authoritySetId,
        uint32 _targetBlock
    ) external {
        bytes32 trustedHeader = blockHeightToHeaderHash[_trustedBlock];
        if (trustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }
        bytes32 authoritySetHash = authoritySetIdToHash[_authoritySetId];
        if (authoritySetHash == bytes32(0)) {
            revert AuthoritySetNotFound();
        }

        require(_targetBlock > _trustedBlock);
        require(_targetBlock - _trustedBlock <= MAX_HEADER_RANGE);
        // Note: This is needed to prevent a long-range attack on the light client.
        require(_targetBlock > latestBlock);

        bytes memory input = abi.encodePacked(
            _trustedBlock,
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

        // Store the data and state commitments for the range (trustedBlock, targetBlock].
        bytes32 key = keccak256(abi.encode(_trustedBlock, _targetBlock));
        dataRootCommitments[key] = dataRootCommitment;
        stateRootCommitments[key] = stateRootCommitment;

        // Update latest block.
        latestBlock = _targetBlock;

        emit HeadUpdate(_targetBlock, targetHeaderHash);

        emit HeaderRangeCommitmentStored(
            _trustedBlock,
            _targetBlock,
            dataRootCommitment,
            stateRootCommitment
        );
    }

    /// @notice Requests a rotate to the next authority set, which starts justifying blocks at
    ///     _epochEndBlock + 1.
    /// @param _epochEndBlock The block height of the epoch end block.
    /// @param _currentAuthoritySetId The authority set id of the current authority set.
    function requestNextAuthoritySetId(
        uint32 _epochEndBlock,
        uint64 _currentAuthoritySetId
    ) external payable {
        // Note: _epochEndBlock must be >= the latestBlock. Can be equal if we've already
        // called step to the _epochEndBlock.
        // This ensures we don't call rotate twice for the same epoch.
        require(_epochEndBlock >= latestBlock);

        bytes32 currentAuthoritySetHash = authoritySetIdToHash[
            _currentAuthoritySetId
        ];
        if (currentAuthoritySetHash == bytes32(0)) {
            revert AuthoritySetNotFound();
        }

        bytes memory input = abi.encodePacked(
            _currentAuthoritySetId,
            currentAuthoritySetHash,
            _epochEndBlock
        );

        bytes memory data = abi.encodeWithSelector(
            this.addNextAuthoritySetId.selector,
            _currentAuthoritySetId,
            _epochEndBlock
        );

        ISuccinctGateway(gateway).requestCall{value: msg.value}(
            rotateFunctionId,
            input,
            address(this),
            data,
            500000
        );
        emit NextAuthoritySetIdRequested(
            _currentAuthoritySetId,
            currentAuthoritySetHash,
            _epochEndBlock
        );
    }

    /// @notice Adds the authority set hash for the next authority set id.
    /// @param _currentAuthoritySetId The authority set id of the current authority set.
    /// @param _epochEndBlock The block height of the epoch end block.
    function addNextAuthoritySetId(
        uint64 _currentAuthoritySetId,
        uint32 _epochEndBlock
    ) external {
        bytes32 currentAuthoritySetHash = authoritySetIdToHash[
            _currentAuthoritySetId
        ];
        // Note: Occurs if requesting a new authority set id that is not the next authority set id.
        if (currentAuthoritySetHash == bytes32(0)) {
            revert AuthoritySetNotFound();
        }

        bytes memory input = abi.encodePacked(
            _currentAuthoritySetId,
            currentAuthoritySetHash,
            _epochEndBlock
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
            newAuthoritySetHash,
            _epochEndBlock
        );
    }
}