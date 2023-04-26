pragma solidity 0.8.16;

import {ILightClient} from "src/lightclient/interfaces/ILightClient.sol";

struct Groth16Proof {
    uint256[2] a;
    uint256[2][2] b;
    uint256[2] c;
}

struct SlotProof {
    uint32 slot;
    bytes[] merkle_proof;  // Proof that it's within the state
}

struct EventListProof {
    bytes encodedEventList;
    bytes[] merkle_proof; // Proof that it's within the state
}

// Currently, the light client will do a step update for every block
struct LightClientStep {
    uint32 blockNumber;
    bytes32 headerRoot;
    bytes32 parentRoot;
    bytes32 executionStateRoot;
    Groth16Proof proof;
}

// Used for a GRANDPA justification finality proof
struct LightClientFinalize {
    uint32 blockNumber;
    bytes32 headerRoot;
    Groth16Proof proof;
    SlotProof slotProof;
}

// For now, we are just going to verify the rotate purely in solidity
struct LightClientRotate {
    uint32 blockNumber;
    EventListProof eventListProof;
    SlotProof slotProof;
}

struct Authorities {
    bytes32 eddsa_pub_key;
    uint64 weight;
}

// TODO:  Need to figure out what types are slots in the avail/substate code.
// TODO:  Should create a new type alias for block numbers

/// @title Avail Light Client
/// @author Succinct Labs
/// @notice Uses Substrate's BABE and GRANDPA protocol to keep up-to-date with block headers from
///         the Avail blockchain. This is done in a gas-efficient manner using zero-knowledge proofs.
contract AvailLightClient is ILightClient, StepVerifier, RotateVerifier {
    uint256 public immutable GENESIS_SLOT;    // May not need this if we can assume this is 0

    uint256 public immutable START_CHECKPOINT_SLOT;
    uint256 public immutable START_CHECKPOINT_BLOCK_NUMBER;
    bytes32 public immutable START_CHECKPOINT_HEADER_ROOT;

    uint16 public immutable NUM_AUTHORITIES = 10;
    uint16 public immutable FINALITY_THRESHOLD = 7;  // This is Ceil(2/3 * NUM_AUTHORITIES)
    uint32 public immutable SLOTS_PER_EPOCH = 180;

    /// @notice The latest block_number the light client has a header for.  This header may not have a 
    ///         grandpa justification submitted for it yet.
    uint32 public head;

    /// @notice The latest block_hash the light client has a header for.  This header may not have a 
    ///         grandpa justification submitted for it yet.
    uint32 public headRoot;

    /// @notice The latest block_number the light client has a finalized header for.
    uint32 public finalized_head = 0;

    /// @notice Maps from a block number to an Avail header root.
    mapping(uint32 => bytes32) public headerRoots;

    /// @notice Maps from a block number to the execution state root.
    mapping(uint32 => bytes32) public executionStateRoots;

    /// @notice Maps from a epoch index to the authorities
    mapping(uint64 => Authorities[NUM_VALIDATORS]) public authorities;

    event HeadUpdate(uint32 indexed block_number, bytes32 indexed root);
    event FinalizedHeadUpdate(uint32 indexed block_number, bytes32 indexed root);
    event AuthoritiesUpdate(uint64 indexed epoch_index);

    constructor(
        uint32 genesisSlot,
        Authorities startCheckpointAuthorities[NUM_AUTHORITIES],
        uint32 startCheckpointSlot,
        uint32 startCheckpointBlockNumber,
        bytes32 startCheckpointHeaderRoot,
    ) {
        GENESIS_SLOT = genesisSlot;
        START_CHECKPOINT_SLOT = startCheckpointSlot;
        START_CHECKPOINT_BLOCK_NUMBER = startCheckpointBlockNumber;
        START_CHECKPOINT_HEADER_ROOT = startCheckpointHeaderRoot;

        start_epoch_index = epoch_index(genesisSlot);
        setAuthorities(start_epoch_index, startCheckpointAuthorities);

        head = startCheckpointBlockNumber;
        finalized_head = startCheckpointBlockNumber;
    }

    function epochIndex(uint32 slot) internal pure returns (uint64) {
        return (slot - genesis_slot) / SLOTS_PER_EPOCH;
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
        if (update.parentRoot != headRoot) {
            revert("Update block doesn't build off of head");
        }

        if (update.blockNumber != head + 1) {
            revert("Update block number not correct");
        }

        // zkLightClientStep(update);

        head = update.blockNumber;
        headRoot = update.headerRoot;
        headerRoots[update.blockNumber] = update.headerRoot;
        executionStateRoots[update.blockNumber] = update.executionStateRoot;

        emit HeadUpdate(update.blockNumber, update.headerRoot);
    }

    /// @notice TODO - This function is not yet implemented
    function zkLightClientStep(LightClientStep memory update) internal view {
        /* Groth16Proof memory proof = update.proof;
        uint256[4] memory inputs = [uint256(t), uint256];
        require(verifyProofStep(proof.a, proof.b, proof.c, inputs)); */
    }

    /// @notice Sets the sync committee for the next sync committeee period.
    /// @dev A commitment to the the next sync committeee is signed by the current sync committee.
    function rotate(LightClientRotate memory update) external {
        LightClientStep memory stepUpdate = update.step;
        bool finalized = processStep(update.step);
        uint256 currentPeriod = getSyncCommitteePeriod(stepUpdate.finalizedSlot);
        uint256 nextPeriod = currentPeriod + 1;

        zkLightClientRotate(update);

        if (finalized) {
            setSyncCommitteePoseidon(nextPeriod, update.syncCommitteePoseidon);
        }
    }


    /// @notice Serializes the public inputs and verifies the rotate proof.
    function zkLightClientRotate(LightClientRotate memory update) internal view {
        Groth16Proof memory proof = update.proof;
        uint256[65] memory inputs;

        uint256 syncCommitteeSSZNumeric = uint256(update.syncCommitteeSSZ);
        for (uint256 i = 0; i < 32; i++) {
            inputs[32 - 1 - i] = syncCommitteeSSZNumeric % 2 ** 8;
            syncCommitteeSSZNumeric = syncCommitteeSSZNumeric / 2 ** 8;
        }
        uint256 finalizedHeaderRootNumeric = uint256(update.step.finalizedHeaderRoot);
        for (uint256 i = 0; i < 32; i++) {
            inputs[64 - i] = finalizedHeaderRootNumeric % 2 ** 8;
            finalizedHeaderRootNumeric = finalizedHeaderRootNumeric / 2 ** 8;
        }
        inputs[32] = uint256(SSZ.toLittleEndian(uint256(update.syncCommitteePoseidon)));

        require(verifyProofRotate(proof.a, proof.b, proof.c, inputs));
    }

    /// @notice Gets the sync committee period from a slot.
    function getSyncCommitteePeriod(uint256 slot) internal view returns (uint256) {
        return slot / SLOTS_PER_PERIOD;
    }

    /// @notice Gets the current slot for the chain the light client is reflecting.
    function getCurrentSlot() internal view returns (uint256) {
        return (block.timestamp - GENESIS_TIME) / SECONDS_PER_SLOT;
    }

    /// @notice Sets the current slot for the chain the light client is reflecting.
    /// @dev Checks if roots exists for the slot already. If there is, check for a conflict between
    ///      the given roots and the existing roots. If there is an existing header but no
    ///      conflict, do nothing. This avoids timestamp renewal DoS attacks.
    function setSlotRoots(uint256 slot, bytes32 finalizedHeaderRoot, bytes32 executionStateRoot)
        internal
    {
        if (headers[slot] != bytes32(0)) {
            if (headers[slot] != finalizedHeaderRoot) {
                consistent = false;
            }
            return;
        }
        if (executionStateRoots[slot] != bytes32(0)) {
            if (executionStateRoots[slot] != executionStateRoot) {
                consistent = false;
            }
            return;
        }

        head = slot;
        headers[slot] = finalizedHeaderRoot;
        executionStateRoots[slot] = executionStateRoot;
        timestamps[slot] = block.timestamp;
        emit HeadUpdate(slot, finalizedHeaderRoot);
    }

    /// @notice Sets the sync committee poseidon for a given period.
    function setSyncCommitteePoseidon(uint256 period, bytes32 poseidon) internal {
        if (
            syncCommitteePoseidons[period] != bytes32(0)
                && syncCommitteePoseidons[period] != poseidon
        ) {
            consistent = false;
            return;
        }
        syncCommitteePoseidons[period] = poseidon;
        emit SyncCommitteeUpdate(period, poseidon);
    }
}
