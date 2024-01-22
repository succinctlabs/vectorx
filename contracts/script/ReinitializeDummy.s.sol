// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.16;

import "forge-std/Script.sol";
import {VectorX} from "../src/VectorX.sol";
import {DummyVectorX} from "../src/DummyVectorX.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

contract ReinitializeScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        bytes32 headerRangeFunctionId = vm.envBytes32(
            "HEADER_RANGE_FUNCTION_ID"
        );
        bytes32 rotateFunctionId = vm.envBytes32("ROTATE_FUNCTION_ID");
        uint32 height = uint32(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = vm.envBytes32("GENESIS_HEADER");
        uint64 authoritySetId = uint64(vm.envUint("GENESIS_AUTHORITY_SET_ID"));
        bytes32 authoritySetHash = vm.envBytes32("GENESIS_AUTHORITY_SET_HASH");

        address gateway = vm.envAddress("GATEWAY_ADDRESS");

        address contractAddress = vm.envAddress("CONTRACT_ADDRESS");

        // Get existing VectorX contract.
        DummyVectorX lightClient = DummyVectorX(contractAddress);

        // Initialize the Vector X light client.
        lightClient.reinitializeContract(
            DummyVectorX.InitParameters({
                guardian: msg.sender,
                gateway: gateway,
                height: height,
                header: header,
                authoritySetId: authoritySetId,
                authoritySetHash: authoritySetHash,
                headerRangeFunctionId: headerRangeFunctionId,
                rotateFunctionId: rotateFunctionId
            })
        );
    }
}
