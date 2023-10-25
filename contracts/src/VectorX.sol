// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IFunctionGateway} from "./interfaces/IFunctionGateway.sol";

contract VectorX {
    // Information related to ZK circuits
    address public gateway;

    // Mappings to store header information and commitments
    mapping(uint32 => bytes32) public blockHeightToHeaderHash;
    mapping(uint32 => uint64) public blockHeightToAuthoritySetId;
    mapping(uint64 => bytes32) public authoritySetIdToHash;
    mapping(bytes32 => bytes32) public dataRootCommitments;
    mapping(bytes32 => bytes32) public stateRootCommitments;

    uint64 public currentAuthoritySetId;
    bytes32 public currentAuthoritySetHash;

    uint32 public head;

    uint32 public constant MAX_RANGE = 128;

    bytes32 public headerRangeFunctionId;

    event HeaderRangeRequested(
        uint32 trustedBlock,
        bytes32 trustedHeader,
        uint64 authoritySetId,
        bytes32 authoritySetHash,
        uint32 targetBlock
    );

    event HeaderRangeFulfilled(
        uint32 trustedBlock,
        uint32 targetBlock,
        bytes32 targetHeaderHash,
        bytes32 dataRootCommitment,
        bytes32 stateRootCommitment
    );

    modifier onlyGateway() {
        require(msg.sender == gateway, "Only gateway can call this function");
        _;
    }

    constructor(address _gateway) {
        gateway = _gateway;
    }

    // TODO: In production, this would be `onlyOwner`
    function updateGateway(address _gateway) external {
        gateway = _gateway;
    }

    // TODO: In production, this would be `onlyOwner`
    function updateHeaderRangeFunctionId(bytes32 _functionId) external {
        headerRangeFunctionId = _functionId;
    }

    // TODO: In production, this would be part of a constructor and/or `onlyOwner`
    function setGensisInfo(
        uint32 _blockHeight,
        bytes32 _header,
        uint64 _authoritySetId,
        bytes32 _authoritySetHash
    ) external {
        blockHeightToHeaderHash[_blockHeight] = _header;
        blockHeightToAuthoritySetId[_blockHeight] = _authoritySetId;
        authoritySetIdToHash[_authoritySetId] = _authoritySetHash;
        currentAuthoritySetId = _authoritySetId;
        currentAuthoritySetHash = _authoritySetHash;
    }

    // Requests a header update and data commitment from the range (trustedBlock, requestedBlock)
    function requestHeaderRange(
        uint32 _trustedBlock,
        uint32 _requestedBlock
    ) external payable {
        bytes32 trustedHeader = blockHeightToHeaderHash[_trustedBlock];
        if (trustedHeader == bytes32(0)) {
            revert("Trusted header not found");
        }
        uint64 authoritySetId = blockHeightToAuthoritySetId[_trustedBlock];
        if (authoritySetId == 0) {
            revert("Authority set ID not found");
        }
        bytes32 authoritySetHash = authoritySetIdToHash[authoritySetId];
        if (authoritySetHash == bytes32(0)) {
            revert("Authority set hash not found");
        }

        require(_requestedBlock > _trustedBlock);
        require(_requestedBlock - _trustedBlock <= MAX_RANGE);
        // NOTE: this is needed to prevent a long-range attack on the light client
        require(_requestedBlock > head);

        bytes memory input = abi.encodePacked(
            _trustedBlock,
            trustedHeader,
            authoritySetId,
            authoritySetHash,
            _requestedBlock
        );

        bytes memory callbackData = abi.encodeWithSelector(
            this.callbackHeaderRange.selector,
            _trustedBlock,
            trustedHeader,
            authoritySetId,
            authoritySetHash,
            _requestedBlock
        );

        IFunctionGateway(gateway).requestCall{value: msg.value}(
            headerRangeFunctionId,
            input,
            address(this),
            callbackData,
            500000
        );
        emit HeaderRangeRequested(
            _trustedBlock,
            trustedHeader,
            authoritySetId,
            authoritySetHash,
            _requestedBlock
        );
    }

    function callbackHeaderRange(
        uint32 _trustedBlock,
        bytes32 _trustedHeader,
        uint64 _authoritySetId,
        bytes32 _authoritySetHash,
        uint32 _targetBlock
    ) external onlyGateway {
        bytes memory input = abi.encodePacked(
            _trustedBlock,
            _trustedHeader,
            _authoritySetId,
            _authoritySetHash,
            _targetBlock
        );

        bytes memory output = IFunctionGateway(gateway).verifiedCall(
            headerRangeFunctionId,
            input
        );

        // abi.encode matches abi.encodePacked for (bytes32, bytes32, bytes32).
        (
            bytes32 target_header_hash,
            bytes32 state_root_commitment,
            bytes32 data_root_commitment
        ) = abi.decode(output, (bytes32, bytes32, bytes32));

        blockHeightToHeaderHash[_targetBlock] = target_header_hash;

        bytes32 key = keccak256(abi.encode(_trustedBlock, _targetBlock));
        dataRootCommitments[key] = data_root_commitment;
        stateRootCommitments[key] = state_root_commitment;

        head = _targetBlock;
        emit HeaderRangeFulfilled(
            _trustedBlock,
            _targetBlock,
            target_header_hash,
            data_root_commitment,
            state_root_commitment
        );
    }

    // Requests a rotate to the next authority set id, which occurs at _epochEndBlock.
    function requestRotate(uint32 _epochEndBlock) external payable {
        bytes32 trustedHeader = blockHeightToHeaderHash[_trustedBlock];
        if (trustedHeader == bytes32(0)) {
            revert("Trusted header not found");
        }
        uint64 authoritySetId = blockHeightToAuthoritySetId[_trustedBlock];
        if (authoritySetId == 0) {
            revert("Authority set ID not found");
        }
        bytes32 authoritySetHash = authoritySetIdToHash[authoritySetId];
        if (authoritySetHash == bytes32(0)) {
            revert("Authority set hash not found");
        }

        require(_requestedBlock > _trustedBlock);
        require(_requestedBlock - _trustedBlock <= MAX_RANGE);
        // NOTE: this is needed to prevent a long-range attack on the light client
        require(_requestedBlock > head);

        IFunctionGateway(gateway).requestCall{value: msg.value}(
            headerRangeFunctionId,
            abi.encodePacked(
                _trustedBlock,
                trustedHeader,
                authoritySetId,
                authoritySetHash,
                _requestedBlock
            ),
            address(this),
            abi.encodeWithSelector(
                this.callbackHeaderRange.selector,
                _trustedBlock,
                trustedHeader,
                authoritySetId,
                authoritySetHash,
                _requestedBlock
            ),
            500000
        );
        emit HeaderRangeRequested(
            _trustedBlock,
            trustedHeader,
            authoritySetId,
            authoritySetHash,
            _requestedBlock
        );
    }

    function callbackRotate(
        uint32 _trustedBlock,
        bytes32 _trustedHeader,
        uint64 _authoritySetId,
        bytes32 _authoritySetHash,
        uint32 _targetBlock
    ) external onlyGateway {
        bytes memory input = abi.encodePacked(
            _trustedBlock,
            _trustedHeader,
            _authoritySetId,
            _authoritySetHash,
            _targetBlock
        );

        bytes memory output = IFunctionGateway(gateway).verifiedCall(
            headerRangeFunctionId,
            input
        );

        // abi.encode matches abi.encodePacked for (bytes32, bytes32, bytes32).
        (
            bytes32 target_header_hash,
            bytes32 state_root_commitment,
            bytes32 data_root_commitment
        ) = abi.decode(output, (bytes32, bytes32, bytes32));

        blockHeightToHeaderHash[_targetBlock] = target_header_hash;

        bytes32 key = keccak256(abi.encode(_trustedBlock, _targetBlock));
        dataRootCommitments[key] = data_root_commitment;
        stateRootCommitments[key] = state_root_commitment;

        head = _targetBlock;
        emit HeaderRangeFulfilled(
            _trustedBlock,
            _targetBlock,
            target_header_hash,
            data_root_commitment,
            state_root_commitment
        );
    }

    function decodePackedData(
        bytes memory _packedData
    ) public pure returns (bytes32, bytes32, bytes32) {
        require(_packedData.length == 96, "Invalid packed data length"); // 3 * 32 = 96

        bytes32 decodedData1;
        bytes32 decodedData2;
        bytes32 decodedData3;

        // Assembly is used to efficiently decode bytes to bytes32
        assembly {
            // Load the first 32 bytes from packedData at position 0x20
            decodedData1 := mload(add(_packedData, 0x20))

            // Load the next 32 bytes
            decodedData2 := mload(add(_packedData, 0x40))

            // Load the last 32 bytes
            decodedData3 := mload(add(_packedData, 0x60))
        }
        return (decodedData1, decodedData2, decodedData3);
    }
}
