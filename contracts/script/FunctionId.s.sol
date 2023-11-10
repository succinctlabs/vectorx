// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {VectorX} from "../src/VectorX.sol";

// forge script script/LightClient.s.sol --rpc-url ${RPC_5} --private-key ${PRIVATE_KEY} --etherscan-api-key ${ETHERSCAN_API_KEY} --broadcast
// forge verify-contract 0xCC7FB73e5df7519E9B7f0A7297db65F52D968d36 VectorX --chain 5 --etherscan-api-key ${ETHERSCAN_API_KEY} --constructor-args "0x000000000000000000000000852a94f8309d445d27222edb1e92a4e83dddd2a8"
contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();
        bytes32 stepFunctionId = bytes32(
            hex"f4b46f5b73762d985f11666d014b5708a79f374e1177856dc83915f788496194"
        );
        bytes32 rotateFunctionId = bytes32(
            hex"6963f81447be45b18aa9ca0abd79d5ed44ff2e91cd7037f5e45c5fb620934b06"
        );

        // Use the below to interact with an already deployed ZK light client
        VectorX lightClient = VectorX(
            0x38dbC93f51Fe296544Ba8a8b629644e2EaBB416a
        );

        lightClient.updateHeaderRangeFunctionId(stepFunctionId);
        lightClient.updateAddNextAuthoritySetFunctionId(rotateFunctionId);
    }
}
