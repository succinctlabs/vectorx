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
            hex"4a8c380126819eaa2c702b0eedcecaf0e744e53c329256ffcfcb136debe3b47a"
        );
        bytes32 rotateFunctionId = bytes32(
            hex"fb9ac718be3fa5610bc96889915a3f8afdfd49a61c119279ee144ba5e90bf007"
        );

        // Use the below to interact with an already deployed ZK light client
        VectorX lightClient = VectorX(
            0x27164a92314c3Ed0b8EF81b8c47eb94B76211E01
        );

        uint32 trustedBlock = 645570;
        uint64 authoritySetId = 616;
        bytes32 authoritySetHash = bytes32(
            hex"be9b8bb905a62631b70c2f5ed2c9988e4580d4bc4e617fa30809a463f77744c0"
        );
        bytes32 header = bytes32(
            hex"ea9dac06abb37b7539fda0f218db407e0ed9317eec96f332f39bebcea2543d6d"
        );

        lightClient.setGenesisInfo(
            trustedBlock,
            header,
            authoritySetId,
            authoritySetHash
        );

        lightClient.updateHeaderRangeFunctionId(stepFunctionId);
        lightClient.updateAddNextAuthoritySetFunctionId(rotateFunctionId);
    }
}
