// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.16;

import "forge-std/Script.sol";
import {VectorX} from "../src/VectorX.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        bytes32 create2Salt = bytes32(vm.envBytes("CREATE2_SALT"));

        bool deploy = vm.envBool("DEPLOY");
        bool upgrade = vm.envBool("UPGRADE");

        VectorX lightClient;
        if (deploy) {
            // Deploy contract
            VectorX lightClientImpl = new VectorX{salt: bytes32(create2Salt)}();

            console.logAddress(address(lightClientImpl));
            lightClient = VectorX(
                address(
                    new ERC1967Proxy{salt: bytes32(create2Salt)}(
                        address(lightClientImpl),
                        ""
                    )
                )
            );

            // Initialize the Vector X light client.
            lightClient.initialize(
                VectorX.InitParameters({
                    guardian: vm.envAddress("GUARDIAN_ADDRESS"),
                    gateway: vm.envAddress("GATEWAY_ADDRESS"),
                    height: uint32(vm.envUint("GENESIS_HEIGHT")),
                    header: vm.envBytes32("GENESIS_HEADER"),
                    authoritySetId: uint64(
                        vm.envUint("GENESIS_AUTHORITY_SET_ID")
                    ),
                    authoritySetHash: vm.envBytes32(
                        "GENESIS_AUTHORITY_SET_HASH"
                    ),
                    headerRangeFunctionId: vm.envBytes32(
                        "HEADER_RANGE_FUNCTION_ID"
                    ),
                    rotateFunctionId: vm.envBytes32("ROTATE_FUNCTION_ID")
                })
            );
        } else if (upgrade) {
            // Deploy contract
            VectorX lightClientImpl = new VectorX{salt: bytes32(create2Salt)}();

            console.logAddress(address(lightClientImpl));
            address existingProxyAddress = vm.envAddress("CONTRACT_ADDRESS");

            lightClient = VectorX(existingProxyAddress);
            lightClient.upgradeTo(address(lightClientImpl));
        } else {
            lightClient = VectorX(vm.envAddress("CONTRACT_ADDRESS"));
        }
        if (vm.envBool("UPDATE_GATEWAY")) {
            lightClient.updateGateway(vm.envAddress("GATEWAY_ADDRESS"));
        }
        if (vm.envBool("UPDATE_GENESIS_STATE")) {
            lightClient.updateGenesisState(
                uint32(vm.envUint("GENESIS_HEIGHT")),
                vm.envBytes32("GENESIS_HEADER"),
                uint64(vm.envUint("GENESIS_AUTHORITY_SET_ID")),
                vm.envBytes32("GENESIS_AUTHORITY_SET_HASH")
            );
        }
        if (vm.envBool("UPDATE_FUNCTION_IDS")) {
            lightClient.updateFunctionIds(
                vm.envBytes32("HEADER_RANGE_FUNCTION_ID"),
                vm.envBytes32("ROTATE_FUNCTION_ID")
            );
        }

        console.logAddress(address(lightClient));
    }
}
