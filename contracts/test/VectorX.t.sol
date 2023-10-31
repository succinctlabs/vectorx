// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/VectorX.sol";

contract VectorXTest is Test {
    VectorX public lightClient;

    function setUp() public {
        lightClient = new VectorX(address(0));
    }

    function testEncoding() public {
        uint64 authoritySetId = 4;
        // bytes32 authoritySetHash = bytes32(
        //     hex"99d276c2bf394325382294e08d3285ec5e3548f3d50deebfb900e0730041a923"
        // );
        uint32 trustedBlock = 10;

        bytes memory encodedBytes = abi.encodePacked(
            authoritySetId,
            // authoritySetHash,
            trustedBlock
        );

        console.logBytes(encodedBytes);
    }
}
