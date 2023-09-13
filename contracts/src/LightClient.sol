pragma solidity 0.8.17;

import "solidity-merkle-trees/src/trie/substrate/Blake2b.sol";
import { Pairing, StepVerifier } from "src/StepVerifier.sol";
import { SubstrateTrie } from "src/SubstrateTrie.sol";
import { NUM_AUTHORITIES, GRANDPA_AUTHORITIES_SETID_KEY, SYSTEM_EVENTS_KEY, EVENT_LIST_PROOF_ADDRESS, AUTHORITY_SETID_PROOF_ADDRESS } from "src/Constants.sol";



function submitHeader(uint256 _startBlock, uint256 _updatedBlock) public {
        require(epoch(_startBlock) == epoch(_updatedBlock), "Invalid epoch");
        bytes32 header = headerHash[_startBlock];
        bytes memory result = IGateway(gateway).zkCall(
            functionId, // skip
            abi.encodePacked(header, _updatedBlock)
        );
        (bytes32 newHeader) = abi.decode(
            result,
            (bytes32)
        );
        headerHash[_updatedBlock] = newHeader;
}


struct Groth16Proof {
    uint256[2] a;
    uint256[2][2] b;
    uint256[2] c;
}

struct Step {
    // This field specifies and proves the last header's authority set id.
    // Note that this is proven aginst the state root of the 2nd to last header (which may already be saved in the smart contract's state).
    // Note that we can move this verfiication logic into the proof field, if we need to save on the gas.
    bytes[] authoritySetIDProof;

    uint32 head;

    bytes32 headHash;

    // This is needed to verify the authoritySetIDProof;
    bytes32 previousStateRoot;

    bytes32 stateRoot;

    bytes32 updatedDataRootsCommitment;

    // This proof is used to verify the following:
    // 1) There exists a sequence of block headers that have the following properties:
    //     a) Those headers are chained together via the parent_hash field and have sequential block numbers.
    //     b) The first header has the block number and parent hash that is stored in the smart contract.
    //     c) Those headers have the submitted headerRoots (basically that those roots are the blake2 digest of those headers).
    //     d) Those headers have the submitted executionStateRoots and dataRoots.
    // 2) There exist a valid GRANDPA justification that finalized the last block in the headers field
    //     a) This GRANDPA justification has been signed by the validators within the authority set ID within the authoritySetIDProof field.
    Groth16Proof proof;
}


// This is used to update the light client's authority set.
// Note that the verification logic is currently done purely in solidity since the Avail testnet's authority set is small,
// but this will need to be converted into a snark proof.
struct Rotate {
    // This field proves the new authority set's ID (proved against the state root of the blockNumber).
    bytes[] authoritySetIDProof;

    // This field proves the scale encoded systems::events list for the block (this will contain the NewAuthorities event).
    bytes[] eventListProof;

    // This field updates the light client's headers up to Rotate.blocknumber.
    //Step step;
}


/// @title Light Client for Avail Blockchain
/// @author Succinct Labs
/// @notice Uses Substrate's BABE and GRANDPA protocol to keep up-to-date with block headers from
///         the Avail blockchain. This is done in a gas-efficient manner using zero-knowledge proofs.
contract LightClient is StepVerifier, SubstrateTrie {
    uint256 public immutable START_CHECKPOINT_BLOCK_NUMBER;
    bytes32 public immutable START_CHECKPOINT_HEADER_HASH;

    /// @notice The latest finalized header's block number.
    uint32 public head;

    /// @notice The latest finalized header hash.
    bytes32 public headHash;

    /// @notice Maps from a block number to the state root.
    mapping(uint32 => bytes32) public stateRoots;

    /// @notice Commitment of the data root merkle mountain trie
    bytes32 public dataRootsCommitment;

    /// @notice The active authority set ID.
    uint64 public activeAuthoritySetID;

    /// @notice Maps from an authority set id to the sha256 hash of the authorities' pub keys
    mapping(uint64 => bytes32) public authoritySetCommitments;

    /// @notice The plonky2 step circuit digest
    uint256[4] public stepCircuitDigest;

    event HeadUpdate(uint32 indexed blockNumber, bytes32 indexed root);
    event AuthoritySetUpdate(uint64 indexed authoritySetID);
    event StepCircuitDigestUpdate(uint256[4] indexed circuitDigest);

    constructor(
        uint32 startHead,
        bytes32 startHeadHash,
        uint64 startAuthoritySetID,
        bytes32 startAuthoritiesCommitment
    ) {
        START_CHECKPOINT_BLOCK_NUMBER = startHead;
        START_CHECKPOINT_HEADER_HASH = startHeadHash;
        head = startHead;
        headHash = startHeadHash;
        emit HeadUpdate(head, headHash);

        activeAuthoritySetID = startAuthoritySetID;
        authoritySetCommitments[activeAuthoritySetID] = startAuthoritiesCommitment;
        emit AuthoritySetUpdate(activeAuthoritySetID);
    }

    /// @notice Updates the step circuit digest.
    function setStepCircuitDigest(uint256[4] memory _stepCircuitDigest) external {
        stepCircuitDigest = _stepCircuitDigest;
        emit StepCircuitDigestUpdate(_stepCircuitDigest);
    }

    function step(Step calldata update) external {
        doStep(update);
    }

    /// @notice Updates the head of the light client with the provided list of headers.
    function doStep(Step calldata update) internal {
        uint256 authoritySetIDProofAddress;
        assembly {
            authoritySetIDProofAddress := add(calldataload(AUTHORITY_SETID_PROOF_ADDRESS), 36)
        }

        // Verify and extract the new authority set id
        (uint64 authoritySetID, ) = VerifySubstrateProof(
                authoritySetIDProofAddress,
                GRANDPA_AUTHORITIES_SETID_KEY,
                update.previousStateRoot,
                false);

        // Verify that the authority set is correct.
        if (authoritySetID != activeAuthoritySetID) {
            revert("Authority set ID is not currently active");
        }

        bytes memory inputBytes = bytes.concat(
            headHash,
            updatedHeadHash,
            dataRootsCommitment,
            updatedDataRootsCommitment,
            previousStateRoot,
            newStateRoot,
            authoritySetCommitments[activeAuthoritySetID],
            bytes8(activeAuthoritySetID),
            bytes4(head),
            bytes4(updatedHead)
        );

        bytes memory _ = IGateway.zkCall(
            MY_FUNCTION_ID,
            inputBytes
        )

        // Note that the snark proof above verifies that the first header is correctly linked to the current head.
        // Update the light client storage
        head = update.head;
        headHash = update.headHash;
        stateRoots[head] = update.stateRoot;
        dataRootsCommitment = update.updatedDataRootsCommitment;

        emit HeadUpdate(head, headHash);
    }

    function verifyStepProof(
        uint32 updatedHead,
        bytes32 updatedHeadHash,
        bytes32 previousStateRoot,
        bytes32 newStateRoot,
        bytes32 updatedDataRootsCommitment,
        Proof memory proof) internal view
    {
        uint256[8] memory inputs;

        // hashInput will be a concatenation of the following
        // 1) current head hash (32 bytes)
        // 2) updated head hash (32 bytes)
        // 3) data root commitment (32 bytes)
        // 4) updated data root commitment (32 bytes)
        // 5) previous state root (32 bytes)
        // 6) new state root (32 bytes)
        // 7) authority set commitment (32 bytes)
        // 8) active authority set id (8 bytes)
        // 9) current head number (4 bytes)
        // 10) updated head number (4 bytes)
        bytes memory hashInput = bytes.concat(
            headHash,
            updatedHeadHash,
            dataRootsCommitment,
            updatedDataRootsCommitment,
            previousStateRoot,
            newStateRoot,
            authoritySetCommitments[activeAuthoritySetID],
            bytes8(activeAuthoritySetID),
            bytes4(head),
            bytes4(updatedHead));

        bytes32[1] memory hashResult;
        assembly {
            let gasLeft := gas()
            pop(staticcall(gasLeft, 0x02, hashInput, 240, hashResult, 32))
        }
        emit HashInput(indexed hashResult, hashInput);

        bytes32 publicInputsHash = hashResult[0];
        inputs[0] = (uint256(publicInputsHash) >> 192) & 0xffffffffffffffff;
        inputs[1] = (uint256(publicInputsHash) >> 128) & 0xffffffffffffffff;
        inputs[2] = (uint256(publicInputsHash) >> 64) & 0xffffffffffffffff;
        inputs[3] = uint256(publicInputsHash) & 0xffffffffffffffff;

        // Add in the plonky2 step circuit digest
        inputs[4] = stepCircuitDigest[0];
        inputs[5] = stepCircuitDigest[1];
        inputs[6] = stepCircuitDigest[2];
        inputs[7] = stepCircuitDigest[3];

        require(verifyProof(proof, inputs));
    }

    /// @notice Rotates the authority set and will optionally execute a step.
    function rotate(Rotate calldata update) external {
        // First call step
        /*
        if (update.step.headers.length > 0) {
            doStep(update.step);
        }
        */

        uint256 authoritySetIDProofAddress;
        uint256 eventListProofAddress;
        assembly {
            authoritySetIDProofAddress := add(calldataload(AUTHORITY_SETID_PROOF_ADDRESS), 36)
            eventListProofAddress := add(calldataload(EVENT_LIST_PROOF_ADDRESS), 36)
        }

        bytes32 stateRoot = 0xb237d8cc3098c339a59f782f9a02137cc98522ee3c7c49b73f2ff6120fabf4da;
        //bytes32 stateRoot = stateRoots[head];

        // Verify and extract the new authority set id
        (uint64 authoritySetID, ) = SubstrateTrie.VerifySubstrateProof(
                authoritySetIDProofAddress,
                GRANDPA_AUTHORITIES_SETID_KEY,
                stateRoot,
                false);

        // Verify and extract the encoded event list
        (, bytes32 digest) = SubstrateTrie.VerifySubstrateProof(
                eventListProofAddress,
                SYSTEM_EVENTS_KEY,
                stateRoot,
                true);

        authoritySetCommitments[authoritySetID] = digest;
        emit AuthoritySetUpdate(activeAuthoritySetID);
    }
}
