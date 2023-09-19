// use ethers::types::H256;
use plonky2x::{
    backend::circuit::Circuit,
    frontend::vars::U32Variable,
    prelude::{
        ArrayVariable, CircuitBuilder, CircuitVariable, GoldilocksField, PlonkParameters,
        RichField, Target, Variable, Witness, WitnessWrite,
    },
};
// use plonky2x_derive::CircuitVariable;

pub const NUM_AUTHORITIES: usize = 76;
pub const QUORUM_SIZE: usize = 51; // 2/3 + 1 of NUM_VALIDATORS

pub const CHUNK_128_BYTES: usize = 128;
pub const MAX_LARGE_HEADER_SIZE: usize = CHUNK_128_BYTES * 52;
pub const MAX_SMALL_HEADER_SIZE: usize = CHUNK_128_BYTES * 10;
pub const HASH_SIZE: usize = 32; // in bytes
pub const PUB_KEY_SIZE: usize = 32; // in bytes
pub const WEIGHT_SIZE: usize = 8; // in bytes

pub const ENCODED_PRECOMMIT_LENGTH: usize = 53;

trait ToField<F: RichField> {
    fn to_field(&self) -> F;
}

pub type U8Variable = U32Variable; // TODO: add a real U8Variable with true range checks
pub type HashVariable = ArrayVariable<U8Variable, 32>;
pub type EncodedPrecommitVariable = ArrayVariable<U8Variable, ENCODED_PRECOMMIT_LENGTH>;

impl<F: RichField, T: CircuitVariable, const N: usize> From<H256>
    for ArrayVariable<T, N> as CircuitVariable>::ValueType
{
    fn from(hash: H256) -> Self {
        let mut bytes = hash.as_bytes().to_vec();
        let fixed: [F; N] = bytes
            .iter()
            .map(|byte| F::from_canonical_u8(byte as u8))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();
        fixed
    }
}

#[derive(Clone, Debug)]
pub struct HeaderVariable {
    pub block_number: Variable,
    pub parent_hash: HashVariable,
    pub state_root: HashVariable,
    pub data_root: HashVariable,
}

#[derive(Clone, Debug)]
pub struct PrecommitVariable {
    pub block_hash: HashVariable,
    pub block_number: Variable,
    pub justification_round: Variable,
    pub authority_set_id: Variable,
}
