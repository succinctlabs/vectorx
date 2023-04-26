pragma solidity 0.8.16;

import "forge-std/Common.sol";
import {
    AvailLightClient,
} from "src/AvailLightClient.sol";

/// @notice Helper contract for parsing the JSON fixture, and converting them to the correct types.
/// @dev    The weird ordering here is because vm.parseJSON require alphabetical ordering of the
///         fields in the struct, and odd types with conversions are due to the way the JSON is
///         handled.
contract AvailLightClientFixture is CommonBase {
    struct Fixture {
        Initial initial;
    }

    struct Initial {
        Authority[AvailLightClient.NUM_AUTHORITIES] authorities;
        uint32 genesisSlot;
        uint32 startCheckpointBlockNumber;
        bytes32 startCheckpointExecutionRoot;
        bytes32 startCheckpointHeaderRoot;
        uint32 startCheckpointSlot;
    }

    function newAvailLightClient(Initial memory initial)
        public
        returns (AvailLightClient)
    {
        return new AvailLightClient(
            initial.genesisSlot,
            initial.startCheckpointAuthorities,
            initial.startCheckpointSlot,
            initial.startCheckpointBlockNumber,
            initial.startCheckpointHeaderRoot,
            initial.startCheckpointExecutionRoot
        );
    }
}
