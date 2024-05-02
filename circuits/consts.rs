// The data root start byte number from the end.
// E.g. data root byte start idx is N - DATA_ROOT_OFFSET_FROM_END where N is the header size.
pub const DATA_ROOT_OFFSET_FROM_END: u32 = 32;

// Number of headers processed per map job for subchain_verification map reduce.
pub const HEADERS_PER_MAP: usize = 8;

// Maximum header size (in blake2b chunks) that can be processed by the circuit.
pub const MAX_HEADER_CHUNK_SIZE: usize = 280;

// Size of a Blake2b chunk (in bytes).
pub const BLAKE2B_CHUNK_SIZE_BYTES: usize = 128;

// Maximum header size (in bytes) that can be processed by the circuit.
// (Data limit is 512KB).
pub const MAX_HEADER_SIZE: usize = MAX_HEADER_CHUNK_SIZE * BLAKE2B_CHUNK_SIZE_BYTES;

// Digest byte size.
pub const HASH_SIZE: usize = 32;

// Length of an Avail validator (pubkey + weight).
pub const VALIDATOR_LENGTH: usize = PUBKEY_LENGTH + WEIGHT_LENGTH;

// Length of an Avail pubkey.
pub const PUBKEY_LENGTH: usize = 32;

// Length of the weight of an Avail validator.
pub const WEIGHT_LENGTH: usize = 8;

// Length of the delay in an Avail header.
pub const DELAY_LENGTH: usize = 4;

// The size in bytes of the section of the prefix corresponding to the consensus engine id.
pub const CONSENSUS_ENGINE_ID_PREFIX_LENGTH: usize = 6;

// The maximum length of the prefix before the encoded new authority set. Includes the consensus
// engine id, the encoded scheduled change message length (up to MAX_COMPACT_UINT_BYTES), the
// schedule change flag, and the encoded new authority set length (up to MAX_COMPACT_UINT_BYTES).
pub const MAX_PREFIX_LENGTH: usize =
    CONSENSUS_ENGINE_ID_PREFIX_LENGTH + MAX_COMPACT_UINT_BYTES + 1 + MAX_COMPACT_UINT_BYTES;

// Length of the justification encoded precommit message.  This is what is
// signed by the authorities.
// Link: https://github.com/availproject/avail/blob/188c20d6a1577670da65e0c6e1c2a38bea8239bb/avail-subxt/src/api_dev.rs#L30549-L30557.
pub const ENCODED_PRECOMMIT_LENGTH: usize = 53;

// The maximum size of the subarray is the max length of the encoded
// authorities + the delay length.
pub const MAX_SUBARRAY_SIZE: usize = MAX_AUTHORITY_SET_SIZE * VALIDATOR_LENGTH + DELAY_LENGTH;

// Max number of authorities this circuit currently supports.
pub const MAX_AUTHORITY_SET_SIZE: usize = 300;

// Can need up to 5 bytes to represent a compact u32.
pub const MAX_COMPACT_UINT_BYTES: usize = 5;
