pragma solidity 0.8.17;

import "forge-std/Common.sol";
import {AvailLightClient, NUM_AUTHORITIES} from "src/AvailLightClient.sol";

/// @notice Helper contract for parsing the JSON fixture, and converting them to the correct types.
/// @dev    The weird ordering here is because vm.parseJSON require alphabetical ordering of the
///         fields in the struct, and odd types with conversions are due to the way the JSON is
///         handled.
contract AvailLightClientFixture is CommonBase {
    struct Fixture {
        Finalize finalize;
        Initial initial;
        Step step;
    }

    struct Initial {
        bytes32[] authorityPubKeys;
        uint64 startCheckpointAuthoritySetID;
        uint32 startCheckpointBlockNumber;
        bytes32 startCheckpointExecutionRoot;
        bytes32 startCheckpointHeaderRoot;
    }

    struct Step {
        uint32 blockNumber;
        bytes32 executionStateRoot;
        bytes32 headerRoot;
        bytes32 parentRoot;
    }

    struct Finalize {
        uint64 authoritySetID;
        uint32 blockNumber;
        bytes32 headerRoot;
        bytes[] merkleProof;
    }

    function newAvailLightClient(Initial memory initial)
        public
        returns (AvailLightClient)
    {
        bytes32[NUM_AUTHORITIES] memory authorities;
        for (uint256 i = 0; i < NUM_AUTHORITIES; i++) {
            authorities[i] = initial.authorityPubKeys[i];
        }

        return new AvailLightClient(
            authorities,
            initial.startCheckpointAuthoritySetID,
            initial.startCheckpointBlockNumber,
            initial.startCheckpointHeaderRoot,
            initial.startCheckpointExecutionRoot
        );
    }
}
