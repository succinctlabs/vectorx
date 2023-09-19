use plonky2x::prelude::{
    ArrayVariable, CircuitBuilder, CircuitVariable, GoldilocksField, PlonkParameters, RichField,
    Target, Variable, Witness, WitnessWrite,
};

use crate::vars::*;

pub trait DecodingMethods {
    fn decode_compact_int(&mut self, compact_bytes: Vec<Target>) -> (Target, Target, Target);

    fn decode_fixed_int(&mut self, bytes: Vec<Target>, num_bytes: usize) -> Target;

    fn decode_header<const S: usize>(
        &mut self,
        header: ArrayVariable<Variable, S>,
        header_length: Variable,
        header_hash: HashVariable,
    ) -> HeaderVariable;

    fn decode_precommit(&mut self, precommit: EncodedPrecommitVariable) -> PrecommitVariable;
}

impl<L: PlonkParameters<D>, const D: usize> DecodingMethods for CircuitBuilder<L, D> {
    fn decode_compact_int(&mut self, compact_bytes: Vec<Target>) -> (Target, Target, Target) {
        todo!();
    }

    // WARNING !!!!
    // Note that this only works for fixed ints that are 64 bytes or less, since the goldilocks field is a little under 64 bytes.
    // So technically, it doesn't even work for 64 byte ints, but for now assume that all u64 values we encounter are less than
    // the goldilocks field size.
    fn decode_fixed_int(&mut self, bytes: Vec<Target>, value_byte_length: usize) -> Target {
        todo!();
    }

    fn decode_header<const S: usize>(
        &mut self,
        header: ArrayVariable<Variable, S>,
        header_length: Variable,
        header_hash: HashVariable,
    ) -> HeaderVariable {
        todo!();
    }

    fn decode_precommit(&mut self, precommit: EncodedPrecommitVariable) -> PrecommitVariable {
        todo!();
    }
}
