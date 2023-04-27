pragma solidity 0.8.17;

struct Groth16Proof {
    uint256[2] a;
    uint256[2][2] b;
    uint256[2] c;
}

struct EpochProof {
    uint64 epochIndex;
    //bytes[] merkleProof;  // Proof that it's within the state root
}

struct EventListProof {
    bytes encodedEventList;
    //bytes[] merkleProof; // Proof that it's within the state
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
    EpochProof epochProof;
}

// For now, we are just going to verify the rotate purely in solidity
struct LightClientRotate {
    uint32 blockNumber;
    EventListProof eventListProof;
}

uint16 constant NUM_AUTHORITIES = 10;

// TODO:  Need to figure out what types are slots in the avail/substate code.
// TODO:  Should create a new type alias for block numbers

/// @title Avail Light Client
/// @author Succinct Labs
/// @notice Uses Substrate's BABE and GRANDPA protocol to keep up-to-date with block headers from
///         the Avail blockchain. This is done in a gas-efficient manner using zero-knowledge proofs.
contract AvailLightClient {
    uint256 public immutable GENESIS_SLOT;    // May not need this if we can assume this is 0

    uint256 public immutable START_CHECKPOINT_SLOT;
    uint256 public immutable START_CHECKPOINT_BLOCK_NUMBER;
    bytes32 public immutable START_CHECKPOINT_HEADER_ROOT;

    uint16 public constant FINALITY_THRESHOLD = 7;  // This is Ceil(2/3 * NUM_AUTHORITIES)
    uint32 public constant SLOTS_PER_EPOCH = 180;

    /// @notice The latest block_number the light client has a header for.  This header may not have a 
    ///         grandpa justification submitted for it yet.
    uint32 public head;

    /// @notice The current epoch index
    uint64 public epochIndex;

    /// @notice The latest block_number the light client has a finalized header for.
    uint32 public finalizedHead;

    /// @notice Maps from a block number to an Avail header root.
    mapping(uint32 => bytes32) public headerRoots;

    /// @notice Maps from a block number to the execution state root.
    mapping(uint32 => bytes32) public executionStateRoots;

    /// @notice Maps from a epoch index to the authorities' pub keys
    mapping(uint64 => bytes32[NUM_AUTHORITIES]) public authorityPuKeys;

    event HeadUpdate(uint32 indexed blockNumber, bytes32 indexed root);
    event FinalizedHeadUpdate(uint32 indexed blockNumber, bytes32 indexed root);
    event AuthoritiesUpdate(uint64 indexed epochIndex);

    constructor(
        uint32 genesisSlot,
        bytes32[NUM_AUTHORITIES] memory startCheckpointAuthorities,
        uint32 startCheckpointSlot,
        uint32 startCheckpointBlockNumber,
        bytes32 startCheckpointHeaderRoot,
        bytes32 startCheckpointExecutionRoot
    ) {
        GENESIS_SLOT = genesisSlot;
        START_CHECKPOINT_SLOT = startCheckpointSlot;
        START_CHECKPOINT_BLOCK_NUMBER = startCheckpointBlockNumber;
        START_CHECKPOINT_HEADER_ROOT = startCheckpointHeaderRoot;

        epochIndex = calculateEpochIndex(startCheckpointSlot);
        setAuthorities(epochIndex, startCheckpointAuthorities);

        head = startCheckpointBlockNumber;
        finalizedHead = startCheckpointBlockNumber;

        headerRoots[startCheckpointBlockNumber] = startCheckpointHeaderRoot;
        executionStateRoots[startCheckpointBlockNumber] = startCheckpointExecutionRoot;
    }

    function calculateEpochIndex(uint32 slot) internal view returns (uint64) {
        return uint64((slot - GENESIS_SLOT) / SLOTS_PER_EPOCH);
    }

    function setAuthorities(uint64 _epochIndex, bytes32[NUM_AUTHORITIES] memory _authorities) internal {
        for (uint16 i = 0; i < NUM_AUTHORITIES; i++) {
            authorityPuKeys[_epochIndex][i]  = _authorities[i];
        }

        emit AuthoritiesUpdate(_epochIndex);
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

        if (update.epochProof.epochIndex != epochIndex) {
            revert("Not in the current epoch");
        }

        // Check to see that we are in the correct epoch
        // verifyEpochProof(update.epochProof);

        // TODO:  Need to implement
        // ZKLightClientFinalize(update);

        finalizedHead = update.blockNumber;

        emit FinalizedHeadUpdate(update.blockNumber, update.headerRoot);
    }
}
