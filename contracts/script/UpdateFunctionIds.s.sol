// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.16;

import "forge-std/Script.sol";
import {VectorX} from "../src/VectorX.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        VectorX lightClient;

        address existingProxyAddress = vm.envAddress("CONTRACT_ADDRESS");

        lightClient = VectorX(existingProxyAddress);

        lightClient.updateFunctionIds(
            vm.envBytes32("HEADER_RANGE_FUNCTION_ID"),
            vm.envBytes32("ROTATE_FUNCTION_ID"),
            uint32(vm.envUint("HEADER_RANGE_COMMITMENT_TREE_SIZE"))
        );
    }
}
