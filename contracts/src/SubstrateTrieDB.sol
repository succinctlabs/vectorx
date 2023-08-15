pragma solidity ^0.8.17;

import "solidity-merkle-trees/src/trie/Bytes.sol";
import "solidity-merkle-trees/src/trie/Node.sol";

import { NibbleSliceOps } from "solidity-merkle-trees/src/trie/NibbleSlice.sol";

import { ScaleCodec } from "solidity-merkle-trees/src/trie/substrate/ScaleCodec.sol";
import "openzeppelin/utils/Strings.sol";

// SPDX-License-Identifier: Apache2

library SubstrateTrieDB {
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

    enum NodeType{ EMPTY, LEAF, NIBBLED_VALUE_BRANCH, NIBBLED_BRANCH, HASHED_LEAF, NIBBLED_HASHED_VALUE_BRANCH }

    function decodeNodeKind(bytes calldata encoded)
        internal
        view 
        returns (NodeType nodeType, uint256 nibbleSize, uint256 bytesRead)
    {
        uint8 i = uint8(encoded[0]);
        bytesRead += 1;
        
        if (i == EMPTY_TRIE) {
            nodeType = NodeType.EMPTY;
        }

        uint8 mask = i & (0x03 << 6);

        uint256 decodeSizeBytesRead;
        if (mask == LEAF_PREFIX_MASK) {
            (nibbleSize, decodeSizeBytesRead) = decodeSize(i, encoded[bytesRead:], 2);
            nodeType = NodeType.LEAF;
        } else if (mask == BRANCH_WITH_MASK) {
            (nibbleSize, decodeSizeBytesRead) = decodeSize(i, encoded[bytesRead:], 2);
            nodeType = NodeType.NIBBLED_VALUE_BRANCH;
        } else if (mask == BRANCH_WITHOUT_MASK) {
            (nibbleSize, decodeSizeBytesRead) = decodeSize(i, encoded[bytesRead:], 2);
            nodeType = NodeType.NIBBLED_BRANCH;
        } else if (mask == EMPTY_TRIE) {
            if (i & (0x07 << 5) == ALT_HASHING_LEAF_PREFIX_MASK) {
                (nibbleSize, decodeSizeBytesRead) = decodeSize(i, encoded[bytesRead:], 3);
                nodeType = NodeType.HASHED_LEAF;
            }  else if (i & (0x0F << 4) == ALT_HASHING_BRANCH_WITH_MASK) {
                (nibbleSize, decodeSizeBytesRead) = decodeSize(i, encoded[bytesRead:], 4);
                nodeType = NodeType.NIBBLED_HASHED_VALUE_BRANCH;
            } else {
                // do not allow any special encoding
                revert("Unallowed encoding");
            }
        }

        bytesRead += decodeSizeBytesRead;
    }

    struct ChildNodeHandle {
        bool isEmpty;
        bool isInline;
        bytes32 digest;
        uint256 inlineStart;
        uint256 inlineLen;
    }

    function decodeChildren(bytes calldata input, uint16 bitmap)
        internal
        pure
        returns (ChildNodeHandle[16] memory children, uint256 bytesRead)
    {
        for (uint256 i = 0; i < 16; i++) {
            if (valueAt(bitmap, i)) {
                children[i].isEmpty = false;

                (uint256 len, uint256 lenBytes) = ScaleCodec.decodeUintCompactCalldata(input[bytesRead:]);
                bytesRead += lenBytes;
                if (len == HASH_LENGTH) {
                    children[i].isInline = false;
                    //children[i].digest = Bytes.toBytes32Calldata(input[bytesRead: bytesRead + HASH_LENGTH]);
                    children[i].digest = Bytes.toBytes32(input[bytesRead: bytesRead + HASH_LENGTH]);
                    bytesRead += HASH_LENGTH;
                } else {
                    children[i].isInline = true;
                    children[i].inlineStart = bytesRead;
                    children[i].inlineLen = len;
                    bytesRead += len;
                }
            } else {
                children[i].isEmpty = true;
            }
        }
    }

    function decodeNibbledBranch(bytes calldata input)
        internal
        pure
        returns (ChildNodeHandle[16] memory children, uint256 childrenStart, uint256 bytesRead)
    {
        uint16 bitmap = uint16(ScaleCodec.decodeUint256(input[0:2]));
        bytesRead += 2;

        childrenStart = bytesRead;
        uint256 childrenByteLen;
        (children, childrenByteLen) = decodeChildren(input[bytesRead:], bitmap);
        bytesRead += childrenByteLen;
    }

    function decodeNibbledHashedValueBranch(bytes calldata input)
        internal
        pure
        returns (bytes32 digest, ChildNodeHandle[16] memory children, uint256 childrenStart, uint256 bytesRead)
    {
        uint16 bitmap = uint16(ScaleCodec.decodeUint256(input[0:2]));
        bytesRead += 2;

        digest = Bytes.toBytes32Calldata(input[bytesRead : bytesRead + HASH_LENGTH]);
        bytesRead += HASH_LENGTH;

        childrenStart = bytesRead;
        uint256 childrenByteLen;
        (children, childrenByteLen) = decodeChildren(input, bitmap);
        bytesRead += childrenByteLen;
    }
    
    function decodeNibbledValueBranch(bytes calldata input)
        internal
        pure
        returns (uint256 valueStart, uint256 valueLen, ChildNodeHandle[16] memory children, uint256 childrenStart, uint256 bytesRead)
    {
        uint16 bitmap = uint16(ScaleCodec.decodeUint256(input[0:2]));
        bytesRead += 2;

        (uint256 valuelen, uint256 valueByteLen) = ScaleCodec.decodeUintCompactCalldata(input[bytesRead:]);
        bytesRead += valueByteLen;
        valueStart = bytesRead;

        bytesRead += valueLen;
        childrenStart = bytesRead;
        uint256 childrenByteLen;
        (children, childrenByteLen) = decodeChildren(input, bitmap);
        bytesRead += childrenByteLen;
    }

    function decodeKey(bytes calldata encoded, uint256 nibbleSize)
        internal
        pure
        returns (uint256 bytesRead)
    {
        bool padding = nibbleSize % NIBBLE_PER_BYTE != 0;
        if (padding && padLeft(uint8(encoded[0])) != 0) {
            revert("Bad Format!");
        }

        uint256 nibbleByteLen = (nibbleSize + (NibbleSliceOps.NIBBLE_PER_BYTE - 1)) / NibbleSliceOps.NIBBLE_PER_BYTE;
        bytesRead = nibbleByteLen;
    }

    function decodeSize(uint8 first, bytes calldata encoded, uint8 prefixMask) internal view returns (uint256 result, uint256 bytesRead) {
        uint8 maxValue = uint8(255 >> prefixMask);
        result = uint256(first & maxValue);

        if (result < maxValue) {
            return (result, 0);
        }

        result -= 1;

        while (result <= NIBBLE_SIZE_BOUND) {
            uint256 n = uint256(uint8(encoded[0]));
            bytesRead += 1;
            if (n < 255) {
                return (result + n + 1, bytesRead);
            }
            result += 255;
        }

        return (NIBBLE_SIZE_BOUND, bytesRead);
    }

    function padLeft(uint8 b) internal pure returns (uint8) {
        return b & ~PADDING_BITMASK;
    }

    function valueAt(uint16 bitmap, uint256 i) internal pure returns (bool) {
        return bitmap  & (uint16(1) << uint16(i)) != 0;
    }
}