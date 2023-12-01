// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IVectorX} from "./interfaces/IVectorX.sol";
import {TimelockedUpgradeable} from "@succinctx/upgrades/TimelockedUpgradeable.sol";
import {ISuccinctGateway} from "@succinctx/interfaces/ISuccinctGateway.sol";

/// @notice VectorX is a light client for Avail's consensus.
/// @dev The light client tracks both the state of Avail's Grandpa consensus and Vector, Avail's
///     data commitment solution.
contract VectorX is IVectorX, TimelockedUpgradeable {
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

    /// @dev Initializes the contract.
    /// @param _guardian The address of the guardian.
    /// @param _gateway The address of the gateway contract.
    /// @param _height The height of the genesis block.
    /// @param _header The header hash of the genesis block.
    /// @param _authoritySetId The authority set id of the genesis block.
    /// @param _authoritySetHash The authority set hash of the genesis block.
    /// @param _headerRangeFunctionId The function ID for header range.
    /// @param _rotateFunctionId The function ID for rotate.
    function initialize(
        address _guardian,
        address _gateway,
        uint32 _height,
        bytes32 _header,
        uint64 _authoritySetId,
        bytes32 _authoritySetHash,
        bytes32 _headerRangeFunctionId,
        bytes32 _rotateFunctionId
    ) external initializer {
        __TimelockedUpgradeable_init(_guardian, _guardian);

        gateway = _gateway;

        blockHeightToHeaderHash[_height] = _header;
        authoritySetIdToHash[_authoritySetId] = _authoritySetHash;
        latestBlock = _height;

        rotateFunctionId = _rotateFunctionId;
        headerRangeFunctionId = _headerRangeFunctionId;
    }

    /// @notice Update the address of the gateway contract.
    function updateGateway(address _gateway) external onlyGuardian {
        gateway = _gateway;
    }

    /// @notice Update the function id for requesting a header range.
    function updateHeaderRangeFunctionId(
        bytes32 _functionId
    ) external onlyGuardian {
        headerRangeFunctionId = _functionId;
    }

    /// @notice Update the function id for requesting a rotate.
    function updateAddNextAuthoritySetFunctionId(
        bytes32 _functionId
    ) external onlyGuardian {
        rotateFunctionId = _functionId;
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
            revert("Trusted header not found");
        }
        // Note: In the case that the trusted block is an epoch end block, the authority set id will
        // be the authority set id of the next epoch.
        bytes32 authoritySetHash = authoritySetIdToHash[_authoritySetId];
        if (authoritySetHash == bytes32(0)) {
            revert("Authority set hash not found");
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
            revert("Trusted header not found");
        }
        bytes32 authoritySetHash = authoritySetIdToHash[_authoritySetId];
        if (authoritySetHash == bytes32(0)) {
            revert("Authority set hash not found");
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
            bytes32 target_header_hash,
            bytes32 state_root_commitment,
            bytes32 data_root_commitment
        ) = abi.decode(output, (bytes32, bytes32, bytes32));

        blockHeightToHeaderHash[_targetBlock] = target_header_hash;

        // Store the data and state commitments for the range (trustedBlock, targetBlock].
        bytes32 key = keccak256(abi.encode(_trustedBlock, _targetBlock));
        dataRootCommitments[key] = data_root_commitment;
        stateRootCommitments[key] = state_root_commitment;

        // Update latest block.
        latestBlock = _targetBlock;

        emit HeadUpdate(_targetBlock, target_header_hash);

        emit HeaderRangeCommitmentStored(
            _trustedBlock,
            _targetBlock,
            data_root_commitment,
            state_root_commitment
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
            revert("Authority set hash not found");
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
            revert("Authority set hash not found");
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

        bytes32 new_authority_set_hash = abi.decode(output, (bytes32));

        // Store the authority set hash for the next authority set id.
        authoritySetIdToHash[
            _currentAuthoritySetId + 1
        ] = new_authority_set_hash;

        emit AuthoritySetStored(
            _currentAuthoritySetId + 1,
            new_authority_set_hash,
            _epochEndBlock
        );
    }
}
