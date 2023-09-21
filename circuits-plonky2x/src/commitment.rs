use plonky2x::frontend::ecc::ed25519::curve::curve_types::{AffinePoint, Curve};
use plonky2x::prelude::{
    ArrayVariable, CircuitBuilder, CircuitVariable, GoldilocksField, PlonkParameters, RichField,
    Target, Variable, Witness, WitnessWrite,
};

pub trait CommitmentMethods<L: PlonkParameters<D>, const D: usize, C: Curve> {
    fn verify_sequential_header_chain<const N: usize>(
        &mut self,
        headers: &ArrayVariable<HeaderVariable, N>,
        hashes: &ArrayVariable<HashVariable, N>,
    );

    fn hash_data_root<const N: usize>(
        &mut self,
        data_roots: &ArrayVariable<HashVariable, N>,
    ) -> HashVariable;
}
