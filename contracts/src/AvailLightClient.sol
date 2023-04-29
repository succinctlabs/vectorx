pragma solidity 0.8.17;

import "solidity-merkle-trees/src/MerklePatricia.sol";
import { AvailEventScaleChunks } from "src/EventScaleChunks.sol";
import { NUM_AUTHORITIES, GRANDPA_AUTHORITIES_SETID_KEY, SYSTEM_EVENTS_KEY } from "src/Constants.sol";

struct Groth16Proof {
    uint256[2] a;
    uint256[2][2] b;
    uint256[2] c;
}

struct AuthoritySetProof {
    uint64 authoritySetID;
    bytes[] merkleProof;  // Proof that it's within the state root
}

struct EventListProof {
    bytes encodedEventList;
    bytes[] merkleProof; // Proof that it's within the state
}

// Currently, the light client will do a step update for every block
struct LightClientStep {
    uint32 blockNumber;
    bytes32 headerRoot;
    bytes32 parentRoot;
    bytes32 executionStateRoot;
    //Groth16Proof proof;
}

// Used for a GRANDPA justification finality proof
struct LightClientFinalize {
    uint32 blockNumber;
    bytes32 headerRoot;
    //Groth16Proof proof;

    // The authority set id from the previous block (and verified against that block's state root)
    AuthoritySetProof authoritySetProof;
}

// For now, we are just going to verify the rotate purely in solidity
struct LightClientRotate {
    uint32 blockNumber;
    EventListProof eventListProof;
    AuthoritySetProof newAuthoritySetProof;
}

// TODO:  Should create a new type alias for block numbers

/// @title Avail Light Client
/// @author Succinct Labs
/// @notice Uses Substrate's BABE and GRANDPA protocol to keep up-to-date with block headers from
///         the Avail blockchain. This is done in a gas-efficient manner using zero-knowledge proofs.
contract AvailLightClient is AvailEventScaleChunks {
    uint256 public immutable START_CHECKPOINT_BLOCK_NUMBER;
    bytes32 public immutable START_CHECKPOINT_HEADER_ROOT;

    /// @notice The latest block_number the light client has a header for.  This header may not have a 
    ///         grandpa justification submitted for it yet.
    uint32 public head;

    /// @notice The latest block_number the light client has a finalized header for.
    uint32 public finalizedHead;

    /// @notice Maps from a block number to an Avail header root.
    mapping(uint32 => bytes32) public headerRoots;

    /// @notice Maps from a block number to the execution state root.
    mapping(uint32 => bytes32) public executionStateRoots;

    /// @notice Maps from a authority set id to the authorities' pub keys
    mapping(uint64 => bytes32[NUM_AUTHORITIES]) public authorityPubKeys;

    event HeadUpdate(uint32 indexed blockNumber, bytes32 indexed root);
    event FinalizedHeadUpdate(uint32 indexed blockNumber, bytes32 indexed root);
    event AuthoritiesUpdate(uint64 indexed epochIndex);

    constructor(
        bytes32[NUM_AUTHORITIES] memory startCheckpointAuthorities,
        uint64 startCheckpointAuthoritySetID,
        uint32 startCheckpointBlockNumber,
        bytes32 startCheckpointHeaderRoot,
        bytes32 startCheckpointExecutionRoot
    ) {
        START_CHECKPOINT_BLOCK_NUMBER = startCheckpointBlockNumber;
        START_CHECKPOINT_HEADER_ROOT = startCheckpointHeaderRoot;

        setAuthorities(startCheckpointAuthoritySetID, startCheckpointAuthorities);

        head = startCheckpointBlockNumber;
        finalizedHead = startCheckpointBlockNumber;

        headerRoots[startCheckpointBlockNumber] = startCheckpointHeaderRoot;
        executionStateRoots[startCheckpointBlockNumber] = startCheckpointExecutionRoot;
    }

    function setAuthorities(uint64 authoritySetID, bytes32[NUM_AUTHORITIES] memory _authorities) internal {
        for (uint16 i = 0; i < NUM_AUTHORITIES; i++) {
            authorityPubKeys[authoritySetID][i]  = _authorities[i];
        }

        emit AuthoritiesUpdate(authoritySetID);
    }

    /// @notice Updates the head of the light client to the provided slot.
    /// @dev The conditions for updating the head of the light client involve checking:
    ///      1) The parent hash is correctly decoded from the header
    ///      2) The execution state root is correctly decoded from the header
    ///      3) The block number if correctly decoded from the header
    ///      4) The header hash is correct
    ///      Note that this function currently assumes that the operator knows that this header is finalized.
    ///      The header will later provate that in the finalize function.
    ///      TODO:  Modify this smart contract to not make this assumptions.  This means that the smart contract will
    ///             basically need to be able to store forks that are not yet finalized.
    function step(LightClientStep memory update) external {
        if (update.blockNumber != head + 1) {
            revert("Update block number not correct");
        }

        if (update.parentRoot != headerRoots[update.blockNumber - 1]) {
            revert("Update block doesn't build off of head");
        }

        // TODO:  Need to implement
        // zkLightClientStep(update);

        head = update.blockNumber;
        headerRoots[update.blockNumber] = update.headerRoot;
        executionStateRoots[update.blockNumber] = update.executionStateRoot;

        emit HeadUpdate(update.blockNumber, update.headerRoot);
    }

    function finalize(LightClientFinalize memory update) external {
        if (update.blockNumber <= finalizedHead) {
            revert("Finalized block number is before the current finalized head");
        }

        // This will check for both a bad inputted headerRoot and for no headerRoot
        if (headerRoots[update.blockNumber] != update.headerRoot) {
            revert("Finalized block header root is not correct");
        }

        // Check to see that we are using the correct authority set
        bytes[] memory keys = new bytes[](1);
        keys[0] = GRANDPA_AUTHORITIES_SETID_KEY;
        bytes memory proof_ret = MerklePatricia.VerifySubstrateProof(executionStateRoots[update.blockNumber-1], 
                                                                    update.authoritySetProof.merkleProof,
                                                                    keys)[0];

        if (ScaleCodec.decodeUint64(proof_ret) != update.authoritySetProof.authoritySetID) {
            revert("Finalized block authority set proof is not correct");
        }

        // TODO:  Need to implement
        // ZKLightClientFinalize(update, update.authoritySetProof.authoritySetID);

        finalizedHead = update.blockNumber;

        emit FinalizedHeadUpdate(update.blockNumber, update.headerRoot);
    }

    function rotate(LightClientRotate memory update) external {
        if (update.blockNumber > finalizedHead) {
            revert("Rotate block number is not finalized yet");
        }

        // TODO.  The two proof verifications can be done in a single batch verification.
        //        We may not need this since the authority rotation will be snarkify-ed.
        // Verify the new authority set id
        bytes[] memory authSetKeys = new bytes[](1);
        authSetKeys[0] = GRANDPA_AUTHORITIES_SETID_KEY;
        bytes memory authSetProofRet = MerklePatricia.VerifySubstrateProof(executionStateRoots[update.blockNumber],
                                                                           update.newAuthoritySetProof.merkleProof,
                                                                           authSetKeys)[0];

        if (ScaleCodec.decodeUint64(authSetProofRet) != update.newAuthoritySetProof.authoritySetID) {
            revert("Incorrect authority set ID committed to the state root");
        }

        // Verify the encoded event list
        bytes[] memory systemEventsKeys = new bytes[](1);
        systemEventsKeys[0] = SYSTEM_EVENTS_KEY;
        bytes memory systemEventsProofRet = MerklePatricia.VerifySubstrateProof(executionStateRoots[update.blockNumber],
                                                                                update.eventListProof.merkleProof,
                                                                                systemEventsKeys)[0];

        // See here for bytes comparison:  https://ethereum.stackexchange.com/a/99342
        if (systemEventsProofRet.length != update.eventListProof.encodedEventList.length ||
            keccak256(systemEventsProofRet) != keccak256(update.eventListProof.encodedEventList)) {
            revert("Incorrect event list committed to the state root");
        }

        bytes32[NUM_AUTHORITIES] memory newAuthorities = decodeAuthoritySet(update.eventListProof.encodedEventList);
        if (newAuthorities.length != NUM_AUTHORITIES) {
            revert("Incorrect number of authorities in the event list");
        }
        setAuthorities(update.newAuthoritySetProof.authoritySetID, newAuthorities);
    }
}
