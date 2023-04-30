pragma solidity 0.8.17;

import "forge-std/Common.sol";
import { NUM_AUTHORITIES } from "src/Constants.sol";
import { Header, LightClient } from "src/LightClient.sol";

/// @notice Helper contract for parsing the JSON fixture, and converting them to the correct types.
/// @dev    The weird ordering here is because vm.parseJSON require alphabetical ordering of the
///         fields in the struct, and odd types with conversions are due to the way the JSON is
///         handled.
contract LightClientFixture is CommonBase {
    struct Initial {
        bytes32[] authorityPubKeys;
        uint64 authoritySetID;
        uint32 blockNumber;
        bytes32 startCheckpointDataRoot;
        bytes32 startCheckpointHeaderHash;
        bytes32 startCheckpointStateRoot;
    }

    struct Rotate {
        bytes encodedEventList;
        bytes[] encodedEventListProof;
        uint64 newAuthoritySetID;
        bytes[] newAuthoritySetIDProof;

        Step step;
    }

    // Fields authoritySetID and merkleProof are for the AuthoritySetIDProof struct.
    struct Step {
        uint64 authoritySetID;
        uint32[] blockNumbers;
        bytes32[] dataRoots;
        bytes32[] headerHashes;
        bytes[] merkleProof;
        bytes32[] stateRoots;
    }

    function newLightClient(Initial memory initial)
        public
        returns (LightClient)
    {
        bytes32[NUM_AUTHORITIES] memory authorities;
        for (uint256 i = 0; i < NUM_AUTHORITIES; i++) {
            authorities[i] = initial.authorityPubKeys[i];
        }

        Header memory header = Header({
            blockNumber: initial.blockNumber,
            dataRoot: initial.startCheckpointDataRoot,
            headerHash: initial.startCheckpointHeaderHash,
            stateRoot: initial.startCheckpointStateRoot
        });

        return new LightClient(
            initial.authoritySetID,
            authorities,
            header
        );
    }
}
