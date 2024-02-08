// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.16;

import "forge-std/Script.sol";
import {VectorX} from "../src/VectorX.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

contract UpdateGenesisScript is Script {
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

        address existingProxyAddress = vm.envAddress("CONTRACT_ADDRESS");

        VectorX lightClient = VectorX(existingProxyAddress);

        // Update the genesis state of the Vector X light client.
        lightClient.updateGenesisState(
            gateway,
            height,
            header,
            authoritySetId,
            authoritySetHash,
            headerRangeFunctionId,
            rotateFunctionId
        );
    }
}
