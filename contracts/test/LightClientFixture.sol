pragma solidity 0.8.17;

import "forge-std/Common.sol";
import { NUM_AUTHORITIES } from "src/Constants.sol";
import { LightClient } from "src/LightClient.sol";

/// @notice Helper contract for parsing the JSON fixture, and converting them to the correct types.
/// @dev    The weird ordering here is because vm.parseJSON require alphabetical ordering of the
///         fields in the struct, and odd types with conversions are due to the way the JSON is
///         handled.
contract LightClientFixture is CommonBase {
    struct Fixture {
        Finalize finalize;
        Initial initial;
        Rotate rotate;
        Step step;
    }

    struct Finalize {
        uint64 authoritySetID;
        uint32 blockNumber;
        bytes32 headerRoot;
        bytes[] merkleProof;
    }

    struct Initial {
        bytes32[] authorityPubKeys;
        uint64 startCheckpointAuthoritySetID;
        uint32 startCheckpointBlockNumber;
        bytes32 startCheckpointExecutionRoot;
        bytes32 startCheckpointHeaderRoot;
    }

    struct Rotate {
        uint32 blockNumber;
        bytes encodedEventList;
        bytes[] encodedEventListProof;
        uint64 newAuthoritySetID;
        bytes[] newAuthoritySetIDProof;
    }

    struct Step {
        uint32 blockNumber;
        bytes32 executionStateRoot;
        bytes32 headerRoot;
        bytes32 parentRoot;
    }

    function newLightClient(Initial memory initial)
        public
        returns (LightClient)
    {
        bytes32[NUM_AUTHORITIES] memory authorities;
        for (uint256 i = 0; i < NUM_AUTHORITIES; i++) {
            authorities[i] = initial.authorityPubKeys[i];
        }

        return new LightClient(
            authorities,
            initial.startCheckpointAuthoritySetID,
            initial.startCheckpointBlockNumber,
            initial.startCheckpointHeaderRoot,
            initial.startCheckpointExecutionRoot
        );
    }
}
