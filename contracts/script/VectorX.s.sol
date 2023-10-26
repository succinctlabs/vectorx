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
        address gateway = address(0x852a94F8309D445D27222eDb1E92A4E83DdDd2a8);
        bytes32 dataCommitmentFunctionId = bytes32(
            0xf21ad9ac1eb903b95ea90d135fe019007cd90508861afaeb73f25d3dfc5dcc01
        );

        // Use the below to interact with an already deployed ZK light client
        // VectorX lightClient = VectorX(
        //     0xB1cdc97E3C9fC29a30da31e49B4e2304b011d631
        // );

        VectorX lightClient = new VectorX(gateway);

        uint32 trustedBlock = 272502;
        bytes32 header = bytes32(
            hex"9a69988124baf188d9d6bbbc579977815086a5d9dfa3b91bafa6d315f31047dc"
        );
        lightClient.setGensisInfo(
            trustedBlock,
            header,
            256,
            bytes32(uint256(1))
        );

        uint32 targetBlock = 272534;

        lightClient.updateHeaderRangeFunctionId(dataCommitmentFunctionId);

        lightClient.requestHeaderRange{value: 0.2 ether}(
            trustedBlock,
            targetBlock
        );
    }
}
