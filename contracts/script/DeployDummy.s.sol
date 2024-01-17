// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.16;

import "forge-std/Script.sol";
import {DummyVectorX} from "../src/DummyVectorX.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
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

        bytes32 create2Salt = bytes32(vm.envBytes("CREATE2_SALT"));

        // Deploy contract
        DummyVectorX lightClientImpl = new DummyVectorX{
            salt: bytes32(create2Salt)
        }();
        DummyVectorX lightClient;
        lightClient = DummyVectorX(
            address(
                new ERC1967Proxy{salt: bytes32(create2Salt)}(
                    address(lightClientImpl),
                    ""
                )
            )
        );
        console.logAddress(address(lightClient));
        console.logAddress(address(lightClientImpl));

        // Initialize the Vector X light client.
        lightClient.initialize(
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
