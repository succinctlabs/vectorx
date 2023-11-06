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
        uint32 trustedBlock = 645570;
        uint64 authoritySetId = 616;
        uint32 targetBlock = 645610;

        bytes memory encodedBytes = abi.encodePacked(
            trustedBlock,
            authoritySetId,
            targetBlock
        );

        console.logBytes(encodedBytes);
    }
}
