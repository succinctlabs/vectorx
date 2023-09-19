use plonky2x::prelude::{
    ArrayVariable, CircuitBuilder, CircuitVariable, GoldilocksField, PlonkParameters, RichField,
    Target, Variable, Witness, WitnessWrite,
};

#[derive(Clone, Debug, CircuitVariable)]
pub struct VerifyHeaderPIs {
    pub block_hash: HashVariable,
    pub block_num: Variable,
    pub parent_hash: HashVariable,
    pub state_root: HashVariable,
    pub data_root: HashVariable,
}

pub trait CircuitBuilderHeader<F: RichField + Extendable<D>, const D: usize> {
    fn process_header<const S: usize>(
        &mut self,
        header: ArrayVariable<Variable, S>,
        header_length: Variable,
    );
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHeader<F, D>
    for CircuitBuilder<F, D>
{
    fn process_header<const S: usize>(
        &mut self,
        header: ArrayVariable<Variable, S>,
        header_length: Variable,
    ) {
        todo!();
    }
}
