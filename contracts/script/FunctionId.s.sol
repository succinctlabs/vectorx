// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {VectorX} from "../src/VectorX.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        bytes32 stepFunctionId = bytes32(
            hex"929183bfe1e3d56617adeed158df6b6770a561236600c4f53a82de95704c8441"
        );
        bytes32 rotateFunctionId = bytes32(
            hex"7b59bfe3dbbaed37a41c1abc71005bd1e3d9da76eb8203ddbddabe916f4945c8"
        );

        // Use the below to interact with an already deployed ZK light client
        VectorX lightClient = VectorX(
            0xc862F17Ebb256679D8b428634B8D1E5D8d9EBf67
        );

        lightClient.updateHeaderRangeFunctionId(stepFunctionId);
        lightClient.updateAddNextAuthoritySetFunctionId(rotateFunctionId);
    }
}
