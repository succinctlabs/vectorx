pragma solidity ^0.8.17;

import "solidity-merkle-trees/src/trie/Bytes.sol";

import "src/SubstrateTrieDB.sol";

// SPDX-License-Identifier: Apache2

library NibbleSliceOpsCalldata {
    uint256 internal constant NIBBLE_PER_BYTE = 2;
    uint256 internal constant BITS_PER_NIBBLE = 4;

    function at(SubstrateTrieDB.NodeCursor memory nodeCursor, uint256 i) internal pure returns (uint256) {
        uint256 ix = i / NIBBLE_PER_BYTE;
        uint256 pad = i % NIBBLE_PER_BYTE;
        uint8 data = Bytes.toUint8Calldata(nodeCursor.cursor + ix);
        return (pad == 1) ? data & 0x0F : data >> BITS_PER_NIBBLE;
    }

    function at(bytes calldata key, uint256 i) internal pure returns (uint256) {
        uint256 ix = i / NIBBLE_PER_BYTE;
        uint256 pad = i % NIBBLE_PER_BYTE;
        uint8 data = uint8(key[ix]);
        return (pad == 1) ? data & 0x0F : data >> BITS_PER_NIBBLE;
     }

    function commonPrefix(
        bytes calldata key, uint256 keyNibbleCursor, uint256 keyNibbleSize,
        SubstrateTrieDB.NodeCursor memory nodeCursor, uint256 nodeKeyNibbleStart, uint256 nodeKeyNibbleLen)
        internal
        pure 
        returns (uint256 commonKeyPrefixLen)
    {
        uint256 keyRemainingLen = keyNibbleSize - keyNibbleCursor;
        uint256 maxNumIter = min(keyRemainingLen, nodeKeyNibbleLen);

        for (uint256 i = 0; i < maxNumIter; i ++) {
            if (at(key, keyNibbleCursor) != at(nodeCursor, nodeKeyNibbleStart)) {
                if (i == 0) {
                    revert("Key not found in proof");
                }
                return i;
            }

            keyNibbleCursor++;
            nodeKeyNibbleStart++;
        }

        return maxNumIter;
    }

    function min(uint256 a, uint256 b) private pure returns (uint256) {
        return (a < b) ? a : b;
    }
}
