// The data root start byte number from the end.
// E.g. data root byte start idx is N - DATA_ROOT_OFFSET_FROM_END where N is the header size.
pub const DATA_ROOT_OFFSET_FROM_END: usize = 132;

// Number of headers processed per map job for subchain_verification map reduce.
pub const HEADERS_PER_MAP: usize = 16;

// Maximum header size (in blake2b chunks) that can be processed by the circuit.
pub const MAX_HEADER_CHUNK_SIZE: usize = 100;

// Maximum header size (in bytes) that can be processed by the circuit.
pub const MAX_HEADER_SIZE: usize = MAX_HEADER_CHUNK_SIZE * 128;

// Digest byte size
pub const HASH_SIZE: usize = 32;

// Length of the justification encoded precommit message.  This is what is
// signed by the authorities.
pub const ENCODED_PRECOMMIT_LENGTH: usize = 53;

// Max number of authorities this circuit currently supports.
pub const MAX_AUTHORITY_SET_SIZE: usize = 80;

// Max number of headers this circuit currently supports.
pub const MAX_NUM_HEADERS: usize = 180;
