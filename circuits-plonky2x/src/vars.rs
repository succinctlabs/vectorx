use plonky2x::prelude::{
    ArrayVariable, CircuitBuilder, CircuitVariable, GoldilocksField, PlonkParameters, RichField,
    Target, Variable, Witness, WitnessWrite,
};

const ENCODED_PRECOMMIT_LENGTH: usize = 0;

trait ToField<F: RichField> {
    fn to_field(&self) -> F;
}

pub type HashVariable = ArrayVariable<Variable<u8>, 32>;
pub type EncodedPrecommitVariable =
    ArrayVariable<RangeCheckedVariable<u8>, ENCODED_PRECOMMIT_LENGTH>;

#[derive(Clone, Debug, CircuitVariable)]
pub struct HeaderVariable {
    pub block_number: Variable,
    pub parent_hash: HashVariable,
    pub state_root: HashVariable,
    pub data_root: HashVariable,
}

#[derive(Clone, Debug, CircuitVariable)]
pub struct PrecommitVariable {
    pub block_hash: HashVariable,
    pub block_number: Variable,
    pub justification_round: Variable,
    pub authority_set_id: Variable,
}
