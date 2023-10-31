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
            hex"98a2381f5efeaf7c3e39d749d6f676df1432487578f393161cebd2b03934f43b"
        );
        bytes32 rotateFunctionId = bytes32(
            hex"b3f1415062a3543bb1c48d9d6a49f9e005fe415d347a5ba63e40bb1235acfd86"
        );

        // Use the below to interact with an already deployed ZK light client
        VectorX lightClient = VectorX(
            0x2DCB17C1EF8BbE1dE386Dc850EcEe1cc3b2aa1b1
        );

        uint32 trustedBlock = 214287;
        uint64 authoritySetId = 202;
        bytes32 authoritySetHash = bytes32(
            hex"99d276c2bf394325382294e08d3285ec5e3548f3d50deebfb900e0730041a923"
        );
        bytes32 header = bytes32(
            hex"1bccd337481d3f37b6059e07b4d903f7186d4448021bce00c54940f92eee28af"
        );

        lightClient.setGenesisInfo(
            trustedBlock,
            header,
            authoritySetId,
            authoritySetHash
        );

        lightClient.updateHeaderRangeFunctionId(stepFunctionId);
        lightClient.updateAddNextAuthoritySetFunctionId(rotateFunctionId);

        // Call rotate
        lightClient.requestNextAuthoritySetId(trustedBlock, authoritySetId);

        // Call step
        // uint32 targetBlock = 214288;

        // lightClient.requestHeaderRange{value: 0.2 ether}(
        //     trustedBlock,
        //     authoritySetId,
        //     targetBlock
        // );
    }
}
