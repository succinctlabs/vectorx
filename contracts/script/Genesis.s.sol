// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {VectorX} from "../src/VectorX.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        // Use the below to interact with an already deployed ZK light client
        VectorX lightClient = VectorX(
            0xc862F17Ebb256679D8b428634B8D1E5D8d9EBf67
        );

        uint32 trustedBlock = 14200;
        uint64 authoritySetId = 6;
        bytes32 authoritySetHash = bytes32(
            hex"98745514f65ae12932902d30b72e0af57b41e43c6c8d2213d651276abbf0ed1b"
        );
        bytes32 header = bytes32(
            hex"5d3064ea08dbb1f51e1c92d6f414b608ebd4e5cd932805aabd70d8059e5b5352"
        );

        lightClient.setGenesisInfo(
            trustedBlock,
            header,
            authoritySetId,
            authoritySetHash
        );
    }
}
