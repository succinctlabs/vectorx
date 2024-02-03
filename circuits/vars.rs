use std::fmt::Debug;

use plonky2x::frontend::curta::ec::point::CompressedEdwardsYVariable;
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::EDDSASignatureVariable;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    ArrayVariable, ByteVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    PlonkParameters, RichField, Variable,
};

use crate::consts::ENCODED_PRECOMMIT_LENGTH;

#[derive(Clone, Debug, CircuitVariable)]
#[value_name(EncodedHeader)]
pub struct EncodedHeaderVariable<const S: usize> {
    pub header_bytes: ArrayVariable<ByteVariable, S>,
    pub header_size: U32Variable,
}

#[derive(Clone, Debug, CircuitVariable)]
#[value_name(HeaderValueType)]
pub struct HeaderVariable {
    pub block_number: U32Variable,
    pub parent_hash: Bytes32Variable,
    pub state_root: Bytes32Variable,
    pub data_root: Bytes32Variable,
}

#[derive(Clone, Debug, CircuitVariable)]
pub struct PrecommitVariable {
    pub block_hash: Bytes32Variable,
    pub block_number: U32Variable,
    pub justification_round: U64Variable,
    pub authority_set_id: U64Variable,
}

#[derive(Clone, Debug, CircuitVariable)]
pub struct SignedPrecommitVariable {
    pub encoded_precommit_message: BytesVariable<ENCODED_PRECOMMIT_LENGTH>,
    pub signature: EDDSASignatureVariable,
}

#[derive(Clone)]
pub struct AuthoritySetSignerVariable {
    pub pub_keys: CompressedEdwardsYVariable, // Array of public keys.
    pub weights: U64Variable, // Array of weights.  These are u64s, but we assume that they are going to be within the golidlocks field.
}

#[derive(Clone, Debug, CircuitVariable)]
#[value_name(RotateStruct)]
pub struct RotateVariable<
    const MAX_HEADER_SIZE: usize,
    const MAX_AUTHORITY_SET_SIZE: usize,
    const MAX_PREFIX_LENGTH: usize,
    const MAX_SUBARRAY_SIZE: usize,
> {
    pub epoch_end_block_number: U32Variable,
    pub current_authority_set_id: U64Variable,
    pub current_authority_set_hash: Bytes32Variable,
    pub target_header: EncodedHeaderVariable<MAX_HEADER_SIZE>,
    pub target_header_num_authorities: Variable,
    pub next_authority_set_start_position: Variable,
    pub new_pubkeys: ArrayVariable<CompressedEdwardsYVariable, MAX_AUTHORITY_SET_SIZE>,
    pub expected_new_authority_set_hash: Bytes32Variable,
    pub prefix_subarray: ArrayVariable<ByteVariable, MAX_PREFIX_LENGTH>,
    pub enc_val_subarray: ArrayVariable<ByteVariable, MAX_SUBARRAY_SIZE>,
}
