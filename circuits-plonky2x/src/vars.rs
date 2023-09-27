use std::fmt::Debug;

use plonky2::plonk::circuit_builder::CircuitBuilder as BaseCircuitBuilder;
pub use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
pub use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
pub use plonky2x::frontend::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::AffinePointTarget;
pub use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    ArrayVariable, ByteVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    Extendable, Field, GoldilocksField, PlonkParameters, RichField, Target, Variable, Witness,
    WitnessWrite,
};
use serde::{Deserialize, Serialize};

pub const NUM_AUTHORITIES: usize = 76;
pub const QUORUM_SIZE: usize = 51; // 2/3 + 1 of NUM_VALIDATORS

pub const CHUNK_128_BYTES: usize = 128;
pub const MAX_LARGE_HEADER_SIZE: usize = CHUNK_128_BYTES * 52;
pub const MAX_SMALL_HEADER_SIZE: usize = CHUNK_128_BYTES * 10;
pub const HASH_SIZE: usize = 32; // in bytes
pub const HASH_SIZE_BITS: usize = 256; // in bits
pub const PUB_KEY_SIZE: usize = 32; // in bytes
pub const WEIGHT_SIZE: usize = 8; // in bytes

pub const ENCODED_PRECOMMIT_LENGTH: usize = 53;

trait ToField<F: RichField> {
    fn to_field(&self) -> F;
}

pub fn to_field_arr<F: RichField, const N: usize>(bytes: Vec<u8>) -> [F; N] {
    let fixed: [F; N] = bytes
        .iter()
        .map(|byte| F::from_canonical_u8(*byte))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    fixed
}

// TODO: put these methods in the actual builder and also replace with more efficient methods
pub fn to_variable_unsafe<F: RichField + Extendable<D>, const D: usize>(
    api: &mut BaseCircuitBuilder<F, D>,
    bytes: &[ByteVariable],
) -> Variable {
    let mut bits_be = bytes
        .iter()
        .flat_map(|b| b.as_bool_targets())
        .collect::<Vec<_>>();
    bits_be.reverse();
    Variable(api.le_sum(bits_be.iter()))
}

pub fn to_variable<F: RichField + Extendable<D>, const D: usize>(
    api: &mut BaseCircuitBuilder<F, D>,
    byte: ByteVariable,
) -> Variable {
    let mut bits_be = byte.as_bool_targets();
    bits_be.reverse();
    Variable(api.le_sum(bits_be.to_vec().iter()))
}

#[derive(Clone, Debug, CircuitVariable)]
#[value_name(EncodedHeader)]
pub struct EncodedHeaderVariable<const S: usize> {
    pub header_bytes: BytesVariable<S>,
    pub header_size: Variable,
}
#[derive(Clone, Debug, CircuitVariable)]
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
    pub justification_round: Variable,
    pub authority_set_id: Variable,
}

pub type Curve = Ed25519;
pub type EDDSAPublicKeyVariable = AffinePointTarget<Curve>;

#[derive(Clone, Debug, CircuitVariable)]
pub struct SignedPrecommitVariable {
    pub encoded_precommit_message: BytesVariable<ENCODED_PRECOMMIT_LENGTH>,
    pub signature: EDDSASignatureTarget<Curve>,
}

#[derive(Clone)]
pub struct AuthoritySetSignerVariable {
    pub pub_keys: EDDSAPublicKeyVariable, // Array of pub keys (in compressed form)
    pub weights: U64Variable, // Array of weights.  These are u64s, but we assume that they are going to be within the golidlocks field.
}
