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

        // Use the below to interact with an already deployed ZK light client
        VectorX lightClient = VectorX(
            0x38dbC93f51Fe296544Ba8a8b629644e2EaBB416a
        );

        uint32 trustedBlock = 1;
        uint64 authoritySetId = 0;
        bytes32 authoritySetHash = bytes32(
            hex"54eb3049b763a6a84c391d53ffb5e93515a171b2dbaaa6a900ec09e3b6bb8dfb"
        );
        bytes32 header = bytes32(
            hex"d9e6fa8a039a40f7764d15a38eed7a346fcae71b61a5d15943a1ea18811c239a"
        );

        lightClient.setGenesisInfo(
            trustedBlock,
            header,
            authoritySetId,
            authoritySetHash
        );
    }
}
