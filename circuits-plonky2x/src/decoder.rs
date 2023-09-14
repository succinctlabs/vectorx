use avail::utils::ENCODED_PRECOMMIT_LENGTH;
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable, DefaultBuilder,
    PlonkParameters, RichField, Variable,
};

// TODO: these should be moved to plonky2x/utils
impl<F: RichField> From<Vec<u8>> for Vec<F> {
    fn from(item: Vec<u8>) -> Self {
        todo!();
    }
}

impl<F: RichField> From<Vec<F>> for Vec<u8> {
    fn from(item: Vec<F>) -> Self {
        todo!();
    }
}

type HashVariable = ArrayVariable<Variable, 32>;
type EncodedPrecommitVariable = ArrayVariable<Variable, ENCODED_PRECOMMIT_LENGTH>;

// TODO: derive CircuitVariable on this
struct HeaderVariable {
    pub block_number: Variable,
    pub parent_hash: HashVariable,
    pub state_root: HashVariable,
    pub data_root: HashVariable,
}

// TODO: derive CircuitVariable on this
struct PrecommitVariable {
    pub block_hash: HashVariable,
    pub block_number: Variable,
    pub justification_round: Variable,
    pub authority_set_id: Variable,
}

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
