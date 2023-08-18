pragma solidity 0.8.17;

uint16 constant NUM_AUTHORITIES = 76;
uint16 constant FINALITY_THRESHOLD = 7;  // This is Ceil(2/3 * NUM_AUTHORITIES)

// TwoX hash of Grandpa::CurrentSetId
bytes32 constant GRANDPA_AUTHORITIES_SETID_KEY = hex'5f9cc45b7a00c5899361e1c6099678dc8a2d09463effcc78a22d75b9cb87dffc';
// TwxX hash of System::Events
bytes32 constant SYSTEM_EVENTS_KEY = hex'26aa394eea5630e07c48ae0c9558cef780d41e5e16056765bc8461851072c9d7';
uint8 constant KEY_BYTE_LENGTH = 32;

// Calldata address that stores the start address for the authority set merkle proof and the 
// system events list merkle proof for the LightClient's step and rotate function (note that
// only the rotate function utilizes a system events merkle proof).
uint8 constant AUTHORITY_SETID_PROOF_ADDRESS = 36;
uint8 constant EVENT_LIST_PROOF_ADDRESS = 68;

uint8 constant NUM_CHILDREN = 16;
uint16 constant MAX_NUM_PROOF_NODES = 50; // worst case scenario, so we avoid unbounded loops

// This struct contains information of the location of the found 
// value during verification.
struct ValueInfo {
    uint256 cursor;     // Address within calldata
    uint256 len;        // length of the value
    bool found;
}