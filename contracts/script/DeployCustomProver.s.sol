// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.16;

import "forge-std/Script.sol";
import {VectorX} from "../src/VectorX.sol";
import {SuccinctGateway} from "@succinctx/SuccinctGateway.sol";
import {ISuccinctGateway, WhitelistStatus} from "@succinctx/interfaces/ISuccinctGateway.sol";
import {ERC1967Proxy} from "@openzeppelin/proxy/ERC1967/ERC1967Proxy.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        SuccinctGateway succinctGateway = SuccinctGateway(
            vm.envAddress("GATEWAY_ADDRESS")
        );

        bytes32 headerRangeFunctionId = vm.envBytes32(
            "HEADER_RANGE_FUNCTION_ID"
        );
        bytes32 rotateFunctionId = vm.envBytes32("ROTATE_FUNCTION_ID");

        address customProver = vm.envAddress("CUSTOM_PROVER");

        succinctGateway.setWhitelistStatus(
            headerRangeFunctionId,
            WhitelistStatus.Custom
        );
        succinctGateway.addCustomProver(headerRangeFunctionId, customProver);

        succinctGateway.setWhitelistStatus(
            rotateFunctionId,
            WhitelistStatus.Custom
        );
        succinctGateway.addCustomProver(rotateFunctionId, customProver);
    }
}
