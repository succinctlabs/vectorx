use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::AffinePointTarget;
use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, GoldilocksField,
    PlonkParameters, RichField, Target, Variable, Witness, WitnessWrite,
};

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

pub type U8Variable = U32Variable;
pub type HashVariable = ArrayVariable<U8Variable, 32>;
pub type EncodedPrecommitVariable = ArrayVariable<U8Variable, ENCODED_PRECOMMIT_LENGTH>;

pub fn to_field_arr<F: RichField, const N: usize>(bytes: Vec<u8>) -> [F; N] {
    let fixed: [F; N] = bytes
        .iter()
        .map(|byte| F::from_canonical_u8(*byte))
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    fixed
}

pub trait ConversionUtils {
    fn to_hash_variable(&mut self, x: Bytes32Variable) -> HashVariable;
}

impl<L: PlonkParameters<D>, const D: usize> ConversionUtils for CircuitBuilder<L, D> {
    fn to_hash_variable(&mut self, x: Bytes32Variable) -> HashVariable {
        let variables =
            x.0 .0
                .iter()
                .map(|x| self.api.le_sum(x.as_bool_targets().iter()))
                .map(|x| U32Variable(Variable(x)))
                .collect();
        ArrayVariable::new(variables)
    }
}

#[derive(Clone, Debug, CircuitVariable)]
pub struct EncodedHeaderVariable<const S: usize> {
    pub header_bytes: ArrayVariable<U8Variable, S>,
    pub header_size: Variable,
}
#[derive(Clone, Debug, CircuitVariable)]
pub struct HeaderVariable {
    pub block_number: U32Variable,
    pub parent_hash: HashVariable,
    pub state_root: HashVariable,
    pub data_root: HashVariable,
}

#[derive(Clone, Debug, CircuitVariable)]
pub struct PrecommitVariable {
    pub block_hash: HashVariable,
    pub block_number: U32Variable,
    pub justification_round: Variable,
    pub authority_set_id: Variable,
}

pub type Curve = Ed25519;
pub type EDDSAPublicKeyVariable = AffinePointTarget<Curve>;

#[derive(Clone, Debug, CircuitVariable)]
pub struct SignedPrecommitVariable {
    pub encoded_precommit_message: EncodedPrecommitVariable,
    pub signature: EDDSASignatureTarget<Curve>,
}

#[derive(Clone)]
pub struct AuthoritySetSignerVariable {
    pub pub_keys: EDDSAPublicKeyVariable, // Array of pub keys (in compressed form)
    pub weights: U64Variable, // Array of weights.  These are u64s, but we assume that they are going to be within the golidlocks field.
}

// pub commitment: HashVariable,
//     pub set_id: U64Variable,
