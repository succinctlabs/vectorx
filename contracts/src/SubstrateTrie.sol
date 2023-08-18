pragma solidity ^0.8.17;

import "solidity-merkle-trees/src/trie/Bytes.sol";
import "solidity-merkle-trees/src/trie/substrate/Blake2b.sol";
import { ScaleCodec } from "solidity-merkle-trees/src/trie/substrate/ScaleCodec.sol";

import { KEY_BYTE_LENGTH, MAX_NUM_PROOF_NODES, NUM_CHILDREN } from "src/Constants.sol";
import { EventDecoder } from "src/EventDecoder.sol";
import { NibbleSliceOps } from "src/NibbleSlice.sol";
import { ValueInfo } from "src/Constants.sol";


// SPDX-License-Identifier: Apache2

enum NodeType{ EMPTY, LEAF, NIBBLED_VALUE_BRANCH, NIBBLED_BRANCH, HASHED_LEAF, NIBBLED_HASHED_VALUE_BRANCH }

// This struct is used by VerifySubstrateProof to save it's current location within the 
// merkle proof as it parses it during verification.
struct NodeCursor {
    bytes32 nodeHash;
    uint256 cursor;    // Address within calldata
    NodeType nodeType;
}

// This struct contains information for each node of the proof.
struct ProofCalldataInfo {
    uint256 calldataAddress;   // start address within calldata
    uint256 len;
    bytes32 digest;
}

// This struct contains information for a child node (16 will be created for each hex value).
struct ChildNodeHandle {
    bool isEmpty;
    bool isInline;
    bytes32 digest;
    uint256 inlineStart;
    uint256 inlineLen;
}

contract SubstrateTrie is EventDecoder {
    uint8 public constant FIRST_PREFIX = 0x00 << 6;
    uint8 public constant PADDING_BITMASK = 0x0F;
    uint8 public constant EMPTY_TRIE = FIRST_PREFIX | (0x00 << 4);
    uint8 public constant LEAF_PREFIX_MASK = 0x01 << 6;
    uint8 public constant BRANCH_WITH_MASK = 0x03 << 6;
    uint8 public constant BRANCH_WITHOUT_MASK = 0x02 << 6;
    uint8 public constant ALT_HASHING_LEAF_PREFIX_MASK = FIRST_PREFIX | (0x01 << 5);
    uint8 public constant ALT_HASHING_BRANCH_WITH_MASK = FIRST_PREFIX | (0x01 << 4);
    uint8 public constant NIBBLE_PER_BYTE = 2;
    uint256 public constant NIBBLE_SIZE_BOUND = uint256(type(uint16).max);
    uint256 public constant BITMAP_LENGTH = 2;
    uint256 public constant HASH_LENGTH = 32;

     /**
      * @notice Verifies substrate specific merkle patricia proofs.
      * @param proofCalldataAddress calldata address of the proof
      * @param key a key to verify and retrieve the value
      * @param root hash of the merkle patricia trie
      * @param authEventListPostProcess bool to run the event list post process
      * @return (uint64, bytes32) a tuple of the found value.  left one is used if authEventListPostProcess == false.  right one if authEventListPostProcess == true.
      */
    function VerifySubstrateProof
    (
        uint256 proofCalldataAddress,
        bytes32 key,
        bytes32 root,
        bool authEventListPostProcess
    )
        internal
        view
        returns (uint64, bytes32)
    {

        // First load the calldata addresses for the proof elements.
        // See the comment in Constants.sol for an example of the calldata layout.

        uint256 proofLen;
        bytes32 proofStartAddress;
        assembly {
            // Load the calldata address of proof
            proofLen := calldataload(proofCalldataAddress)
            proofStartAddress := add(proofCalldataAddress, 32)
        }

        ProofCalldataInfo[] memory proofCalldataInfo = new ProofCalldataInfo[](proofLen);

        uint16 i;
        for (i = 0; i < proofLen; i++) {
            uint256 nodeStartAddress;
            uint256 nodeLen;

            assembly {
                let nodeStartAddressAddress := add(proofStartAddress, mul(i, 32))
                nodeStartAddress := add(calldataload(nodeStartAddressAddress), proofStartAddress)
                nodeLen := calldataload(nodeStartAddress)
            }

            bytes memory node = new bytes(nodeLen);
            assembly {
                calldatacopy(node, nodeStartAddress, add(nodeLen, 32))

                // add 32 bytes since the first word is the node length
                nodeStartAddress := add(nodeStartAddress, 32)
            }

            proofCalldataInfo[i].calldataAddress = nodeStartAddress;
            proofCalldataInfo[i].len = nodeLen;

            // TODO:  Make blake2b work with calldata
            bytes32 nodeDigest = Bytes.toBytes32(Blake2b.blake2b(node, 32));

            proofCalldataInfo[i].digest = nodeDigest;
        }

        // The cursor location of the passed in key.  Note that this cursor is in units of nibbles (each nibble is a hex value).
        // So there are 2 nibbles per byte.
        uint256 keyNibbleCursor;

        // Start with looking up the node that maps to the root hash
        NodeCursor memory nodeCursor;
        nodeCursor.nodeHash = root;
        nodeCursor.cursor = proofCalldataInfo[TrieNodeLookup(proofCalldataInfo, root)].calldataAddress;

        ValueInfo memory valueInfo;
        ChildNodeHandle[NUM_CHILDREN] memory children;
        for (i = 0; i < MAX_NUM_PROOF_NODES; i++) {
            keyNibbleCursor = processNode(
                nodeCursor,
                valueInfo,
                children,
                proofCalldataInfo,
                keyNibbleCursor,
                key
            );

            if (valueInfo.found) {
                break;
            }
        }

        // If the key is for the authority event list, then decode it and hash the result
        // If the key is for the authority set id, then decode it to a uint64
        bytes32 authoritySetDigest;
        uint64 authoritySetId;
        if (authEventListPostProcess) {
            authoritySetDigest = decodeAuthoritySet(valueInfo);
        } else {
            authoritySetId = ScaleCodec.decodeUint64Calldata(valueInfo.cursor);
        }

        return (authoritySetId, authoritySetDigest);
    }


    function processNode(
        NodeCursor memory nodeCursor,
        ValueInfo memory valueInfo,
        ChildNodeHandle[NUM_CHILDREN] memory children,
        ProofCalldataInfo[] memory proofCalldataInfo,
        uint256 keyNibbleCursor,
        bytes32 key
    )
        internal
        pure
        returns (uint256 updatedKeyNibbleCursor)
    {
        uint256 nibbleSize;
        nibbleSize = decodeNodeKind(nodeCursor);

        if (nodeCursor.nodeType == NodeType.EMPTY) {
            revert("Empty node found in proof");
        }

        // Get the key nibble from the node
        uint256 commonKeyPrefixLen = 0;
        if (nibbleSize > 0) {
            uint256 nibbleByteLen = decodeKey(nodeCursor, nibbleSize);
            commonKeyPrefixLen = NibbleSliceOps.commonPrefix(
                key, keyNibbleCursor, KEY_BYTE_LENGTH * 2,
                nodeCursor, nibbleSize % NIBBLE_PER_BYTE, nibbleSize);
            nodeCursor.cursor += nibbleByteLen;
        }

        bool keyNibbleFullMatch = (commonKeyPrefixLen == KEY_BYTE_LENGTH * 2 - keyNibbleCursor);
        if (keyNibbleFullMatch) {
            if (!(nodeCursor.nodeType == NodeType.NIBBLED_BRANCH)) {
                extractValue(
                    nodeCursor,
                    valueInfo,
                    children,
                    proofCalldataInfo
                );
            } else {
                revert("Key not found in proof");
            }
        } else {
            if (nodeCursor.nodeType == NodeType.NIBBLED_BRANCH ||
                nodeCursor.nodeType == NodeType.NIBBLED_HASHED_VALUE_BRANCH ||
                nodeCursor.nodeType == NodeType.NIBBLED_VALUE_BRANCH) {
                    uint256 at = keyNibbleCursor + nibbleSize;
                    uint256 index = NibbleSliceOps.at(key, at);
                    extractChildren(
                        nodeCursor,
                        children,
                        proofCalldataInfo,
                        index
                    );
            } else {
                revert("Key not found in proof");
            }
        }

        if (!valueInfo.found) {
            // Increment the key
            updatedKeyNibbleCursor = keyNibbleCursor + (nibbleSize + 1);
        }
    }

    function extractValue(
        NodeCursor memory nodeCursor,
        ValueInfo memory valueInfo,
        ChildNodeHandle[NUM_CHILDREN] memory children,
        ProofCalldataInfo[] memory proofCalldataInfo
    ) 
        internal
        pure
    {
        if (nodeCursor.nodeType == NodeType.LEAF) {
            // Get the size of the value
            uint256 bytesRead;
            (valueInfo.len, bytesRead) = ScaleCodec.decodeUintCompactCalldata(nodeCursor.cursor);
            valueInfo.cursor = nodeCursor.cursor + bytesRead;
            valueInfo.found = true;

        } else if (nodeCursor.nodeType == NodeType.HASHED_LEAF) {
            bytes32 nodeHash = Bytes.toBytes32Calldata(nodeCursor.cursor);
            uint256 idx = TrieNodeLookup(proofCalldataInfo, nodeHash);
            valueInfo.cursor = proofCalldataInfo[idx].calldataAddress;
            valueInfo.len = proofCalldataInfo[idx].len;
            valueInfo.found = true;

        } else if (
            nodeCursor.nodeType == NodeType.NIBBLED_HASHED_VALUE_BRANCH ||
            nodeCursor.nodeType == NodeType.NIBBLED_VALUE_BRANCH) {

            if (nodeCursor.nodeType == NodeType.NIBBLED_HASHED_VALUE_BRANCH) {
                (bytes32 nodeHash, ) = decodeNibbledHashedValueBranch(children, nodeCursor);
                uint256 idx = TrieNodeLookup(proofCalldataInfo, nodeHash);
                valueInfo.cursor = proofCalldataInfo[idx].calldataAddress;
                valueInfo.len = proofCalldataInfo[idx].len;
                valueInfo.found = true;

            } else if (nodeCursor.nodeType == NodeType.NIBBLED_VALUE_BRANCH) {
                uint256 nodeValueStart;
                uint256 nodeValueLen;
                (nodeValueStart, nodeValueLen, ) = decodeNibbledValueBranch(children, nodeCursor);
                valueInfo.cursor = nodeValueStart;
                valueInfo.len = nodeValueLen;
                valueInfo.found = true;
            }
        }
    }

    function extractChildren(
        NodeCursor memory nodeCursor,
        ChildNodeHandle[NUM_CHILDREN] memory children,
        ProofCalldataInfo[] memory proofCalldataInfo,
        uint256 index
    )
        internal
        pure
    {
        uint256 childrenStart;
        if (nodeCursor.nodeType == NodeType.NIBBLED_BRANCH) {
            childrenStart = decodeNibbledBranch(children, nodeCursor);
        } else if (nodeCursor.nodeType == NodeType.NIBBLED_HASHED_VALUE_BRANCH) {
            (, childrenStart) = decodeNibbledHashedValueBranch(children, nodeCursor);
        } else if (nodeCursor.nodeType == NodeType.NIBBLED_VALUE_BRANCH) {
            (, , childrenStart) = decodeNibbledValueBranch(children, nodeCursor);
        }

        if (!children[index].isEmpty) {
            if (children[index].isInline) {
                nodeCursor.cursor = children[index].inlineStart;
            } else {
                nodeCursor.nodeHash = children[index].digest;
                uint256 idx = TrieNodeLookup(proofCalldataInfo, nodeCursor.nodeHash);
                nodeCursor.cursor = proofCalldataInfo[idx].calldataAddress;
            }
        } else {
            revert("Key not found in proof");
        }
    }

    function TrieNodeLookup(ProofCalldataInfo[] memory proofCalldataInfo, bytes32 digest)
        internal
        pure
        returns (uint256 i)
    {
        for (i = 0; i < proofCalldataInfo.length; i++) {
            if (proofCalldataInfo[i].digest == digest) {
                return i;
            }
        }
        revert("TrieNodeLookup failed");
    }    

    function decodeNodeKind(NodeCursor memory nodeCursor)
        internal
        pure 
        returns (uint256 nibbleSize)
    {
        uint8 i = ScaleCodec.decodeUint8Calldata(nodeCursor.cursor);
        nodeCursor.cursor += 1;
        
        if (i == EMPTY_TRIE) {
            nodeCursor.nodeType = NodeType.EMPTY;
        }

        uint8 mask = i & (0x03 << 6);

        if (mask == LEAF_PREFIX_MASK) {
            nibbleSize = decodeSize(i, nodeCursor, 2);
            nodeCursor.nodeType = NodeType.LEAF;
        } else if (mask == BRANCH_WITH_MASK) {
            nibbleSize = decodeSize(i, nodeCursor, 2);
            nodeCursor.nodeType = NodeType.NIBBLED_VALUE_BRANCH;
        } else if (mask == BRANCH_WITHOUT_MASK) {
            nibbleSize = decodeSize(i, nodeCursor, 2);
            nodeCursor.nodeType = NodeType.NIBBLED_BRANCH;
        } else if (mask == EMPTY_TRIE) {
            if (i & (0x07 << 5) == ALT_HASHING_LEAF_PREFIX_MASK) {
                nibbleSize = decodeSize(i, nodeCursor, 3);
                nodeCursor.nodeType = NodeType.HASHED_LEAF;
            }  else if (i & (0x0F << 4) == ALT_HASHING_BRANCH_WITH_MASK) {
                nibbleSize = decodeSize(i, nodeCursor, 4);
                nodeCursor.nodeType = NodeType.NIBBLED_HASHED_VALUE_BRANCH;
            } else {
                // do not allow any special encoding
                revert("Unallowed encoding");
            }
        }
    }

    function decodeChildren(ChildNodeHandle[16] memory children, uint16 bitmap, NodeCursor memory nodeCursor)
        internal
        pure
    {
        for (uint256 i = 0; i < 16; i++) {
            if (valueAt(bitmap, i)) {
                children[i].isEmpty = false;

                (uint256 len, uint256 lenBytes) = ScaleCodec.decodeUintCompactCalldata(nodeCursor.cursor);
                nodeCursor.cursor += lenBytes;

                if (len == HASH_LENGTH) {
                    children[i].isInline = false;
                    children[i].digest = Bytes.toBytes32Calldata(nodeCursor.cursor);
                } else {
                    children[i].isInline = true;
                    children[i].inlineStart = nodeCursor.cursor;
                    children[i].inlineLen = len;
                }

                nodeCursor.cursor += len;
            } else {
                children[i].isEmpty = true;
            }
        }
    }

    function decodeNibbledBranch(ChildNodeHandle[16] memory children, NodeCursor memory nodeCursor)
        internal
        pure
        returns (uint256 childrenStart)
    {
        uint16 bitmap = ScaleCodec.decodeUint16Calldata(nodeCursor.cursor);
        nodeCursor.cursor += 2;

        childrenStart = nodeCursor.cursor;
        decodeChildren(children, bitmap, nodeCursor);
    }

    function decodeNibbledHashedValueBranch(ChildNodeHandle[16] memory children, NodeCursor memory nodeCursor)
        internal
        pure
        returns (bytes32 digest, uint256 childrenStart)
    {
        uint16 bitmap = ScaleCodec.decodeUint16Calldata(nodeCursor.cursor);
        nodeCursor.cursor += 2;

        digest = Bytes.toBytes32Calldata(nodeCursor.cursor);
        nodeCursor.cursor += HASH_LENGTH;

        childrenStart = nodeCursor.cursor;
        decodeChildren(children, bitmap, nodeCursor);
    }
    
    function decodeNibbledValueBranch(ChildNodeHandle[16] memory children, NodeCursor memory nodeCursor)
        internal
        pure
        returns (uint256 valueStart, uint256 valueLen, uint256 childrenStart)
    {
        uint16 bitmap = ScaleCodec.decodeUint16Calldata(nodeCursor.cursor);
        nodeCursor.cursor += 2;

        ( ,uint256 valueByteLen) = ScaleCodec.decodeUintCompactCalldata(nodeCursor.cursor);
        nodeCursor.cursor += valueByteLen;
        valueStart = nodeCursor.cursor;

        nodeCursor.cursor += valueLen;
        childrenStart = nodeCursor.cursor;

        decodeChildren(children, bitmap, nodeCursor);
    }

    function decodeKey(NodeCursor memory nodeCursor, uint256 nibbleSize)
        internal
        pure
        returns (uint256 nibbleByteLen)
    {
        bool padding = nibbleSize % NIBBLE_PER_BYTE != 0;
        uint8 firstChar = ScaleCodec.decodeUint8Calldata(nodeCursor.cursor);
        if (padding && padLeft(firstChar) != 0) {
            revert("Bad Format!");
        }

        nibbleByteLen = (nibbleSize + (NibbleSliceOps.NIBBLE_PER_BYTE - 1)) / NibbleSliceOps.NIBBLE_PER_BYTE;
    }

    function decodeSize(uint8 first, NodeCursor memory nodeCursor, uint8 prefixMask) internal pure returns (uint256 result) {
        uint8 maxValue = uint8(255 >> prefixMask);
        result = uint256(first & maxValue);

        if (result < maxValue) {
            return result;
        }

        result -= 1;

        while (result <= NIBBLE_SIZE_BOUND) {
            uint256 n = uint256(ScaleCodec.decodeUint8Calldata(nodeCursor.cursor));
            nodeCursor.cursor += 1;
            if (n < 255) {
                return (result + n + 1);
            }
            result += 255;
        }

        return NIBBLE_SIZE_BOUND;
    }

    function padLeft(uint8 b) internal pure returns (uint8) {
        return b & ~PADDING_BITMASK;
    }

    function valueAt(uint16 bitmap, uint256 i) internal pure returns (bool) {
        return bitmap  & (uint16(1) << uint16(i)) != 0;
    }
}