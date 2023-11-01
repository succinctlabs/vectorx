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
            hex"3503f80d2000a387d3f19ba5ae616ee31f8455e6d13c835ee4c4404db3bb449e"
        );
        bytes32 rotateFunctionId = bytes32(
            hex"d78926e1a401e80cff31715d3dbad782ff8e7cdc83fa436f6e03e3e07cd7a7b4"
        );

        // Use the below to interact with an already deployed ZK light client
        VectorX lightClient = VectorX(
            0x14588DB3A468Aeb603379B0DA881a748971A94B8
        );

        uint32 trustedBlock = 215367;
        uint64 authoritySetId = 203;
        bytes32 authoritySetHash = bytes32(
            hex"99d276c2bf394325382294e08d3285ec5e3548f3d50deebfb900e0730041a923"
        );
        bytes32 header = bytes32(
            hex"f1fc366868ae66403816faf4778769f4344b7f9f2ac6f705350588aba5c1b7b7"
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
        // lightClient.requestNextAuthoritySetId(trustedBlock, authoritySetId);

        // Call step
        // uint32 targetBlock = 214288;

        // lightClient.requestHeaderRange{value: 0.2 ether}(
        //     trustedBlock,
        //     authoritySetId,
        //     targetBlock
        // );
    }
}
