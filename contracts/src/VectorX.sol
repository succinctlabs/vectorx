// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {IFunctionGateway} from "./interfaces/IFunctionGateway.sol";

contract VectorX {
    // Information related to ZK circuits
    address public gateway;
    mapping(string => bytes32) public functionNameToId;

    // Mappings to store header information and commitments
    mapping(uint32 => bytes32) public blockHeightToHeaderHash;
    mapping(uint32 => uint64) public blockHeightToAuthoritySetId;
    mapping(uint64 => bytes32) public authoritySetIdToHash;
    mapping(bytes32 => bytes32) public dataRootCommitments;
    mapping(bytes32 => bytes32) public stateRootCommitments;

    uint32 public head;

    uint32 public constant MAX_RANGE = 128;

    event DataCommitmentRequested(
        uint32 trustedBlock,
        bytes32 trustedHeader,
        uint64 authoritySetId,
        bytes32 authoritySetHash,
        uint32 targetBlock
    );

    event DataCommitmentFulfilled(
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
    function updateFunctionId(
        string memory name,
        bytes32 _functionId
    ) external {
        functionNameToId[name] = _functionId;
    }

    // TODO: In proudction, this would be part of a constructor and/or `onlyOwner`
    function setGensisInfo(
        uint32 blockHeight,
        bytes32 header,
        uint64 authoritySetId,
        bytes32 authoritySetHash
    ) external {
        blockHeightToHeaderHash[blockHeight] = header;
        blockHeightToAuthoritySetId[blockHeight] = authoritySetId;
        authoritySetIdToHash[authoritySetId] = authoritySetHash;
    }

    // Requests a header update and data commitment from the range (trustedBlock, requestedBlock)
    function requestDataCommitment(
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
        bytes32 id = functionNameToId["dataCommitment"];
        if (id == bytes32(0)) {
            revert("Function ID for dataCommitment not found");
        }
        require(_requestedBlock > _trustedBlock);
        require(_requestedBlock - _trustedBlock <= MAX_RANGE);
        // NOTE: this is needed to prevent a long-range attack on the light client
        require(_requestedBlock > head);

        IFunctionGateway(gateway).requestCall{value: msg.value}(
            id,
            abi.encodePacked(
                _trustedBlock,
                trustedHeader,
                authoritySetId,
                authoritySetHash,
                _requestedBlock
            ),
            address(this),
            abi.encodeWithSelector(
                this.callbackDataCommitment.selector,
                _trustedBlock,
                trustedHeader,
                authoritySetId,
                authoritySetHash,
                _requestedBlock
            ),
            500000
        );
        emit DataCommitmentRequested(
            _trustedBlock,
            trustedHeader,
            authoritySetId,
            authoritySetHash,
            _requestedBlock
        );
    }

    function callbackDataCommitment(
        uint32 trustedBlock,
        bytes32 trustedHeader,
        uint64 authoritySetId,
        bytes32 authoritySetHash,
        uint32 targetBlock
    ) external onlyGateway {
        bytes memory input = abi.encodePacked(
            trustedBlock,
            trustedHeader,
            authoritySetId,
            authoritySetHash,
            targetBlock
        );

        bytes memory requestResult = IFunctionGateway(gateway).verifiedCall(
            functionNameToId["dataCommitment"],
            input
        );

        // abi.encode matches abi.encodePacked for (bytes32, bytes32, bytes32).
        (
            bytes32 target_header_hash,
            bytes32 state_root_commitment,
            bytes32 data_root_commitment
        ) = abi.decode(requestResult, (bytes32, bytes32, bytes32));

        blockHeightToHeaderHash[targetBlock] = target_header_hash;

        bytes32 key = keccak256(abi.encode(trustedBlock, targetBlock));
        dataRootCommitments[key] = data_root_commitment;
        stateRootCommitments[key] = state_root_commitment;

        head = targetBlock;
        emit DataCommitmentFulfilled(
            trustedBlock,
            targetBlock,
            target_header_hash,
            data_root_commitment,
            state_root_commitment
        );
    }

    function decodePackedData(
        bytes memory packedData
    ) public pure returns (bytes32, bytes32, bytes32) {
        require(packedData.length == 96, "Invalid packed data length"); // 3 * 32 = 96

        bytes32 decodedData1;
        bytes32 decodedData2;
        bytes32 decodedData3;

        // Assembly is used to efficiently decode bytes to bytes32
        assembly {
            // Load the first 32 bytes from packedData at position 0x20
            decodedData1 := mload(add(packedData, 0x20))

            // Load the next 32 bytes
            decodedData2 := mload(add(packedData, 0x40))

            // Load the last 32 bytes
            decodedData3 := mload(add(packedData, 0x60))
        }
        return (decodedData1, decodedData2, decodedData3);
    }
}
