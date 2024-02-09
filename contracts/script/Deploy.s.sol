// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.16;

import "forge-std/Script.sol";
import {VectorX} from "../src/VectorX.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

// Deploy or upgrade a new contract.
// If UPGRADE_VIA_EOA is true, the existing contract address must be provided. It will update
// the contract to the new implementation with the new parameters.
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

        bytes32 CREATE2_SALT = bytes32(vm.envBytes("CREATE2_SALT"));

        bool UPGRADE = vm.envBool("UPGRADE_VIA_EOA");
        address existingProxyAddress = vm.envAddress("CONTRACT_ADDRESS");

        // Deploy contract
        VectorX lightClientImpl = new VectorX{salt: bytes32(CREATE2_SALT)}();

        console.logAddress(address(lightClientImpl));

        VectorX lightClient;
        if (!UPGRADE) {
            lightClient = VectorX(
                address(
                    new ERC1967Proxy{salt: bytes32(CREATE2_SALT)}(
                        address(lightClientImpl),
                        ""
                    )
                )
            );

            // Initialize the Vector X light client.
            lightClient.initialize(
                VectorX.InitParameters({
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
        } else {
            lightClient = VectorX(existingProxyAddress);
            lightClient.upgradeTo(address(lightClientImpl));

            lightClient.updateGenesisState(height, header, authoritySetId, authoritySetHash);
            lightClient.updateGateway(gateway);
            lightClient.updateFunctionIds(headerRangeFunctionId, rotateFunctionId);
        }

        console.logAddress(address(lightClient));
    }
}
