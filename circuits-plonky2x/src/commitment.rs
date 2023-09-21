use plonky2x::frontend::ecc::ed25519::curve::curve_types::{AffinePoint, Curve};
use plonky2x::prelude::{
    ArrayVariable, CircuitBuilder, CircuitVariable, GoldilocksField, PlonkParameters, RichField,
    Target, Variable, Witness, WitnessWrite,
};

pub trait CommitmentMethods<L: PlonkParameters<D>, const D: usize, C: Curve> {
    fn verify_sequential_header_chain<const N: usize>(
        &mut self,
        headers: &ArrayVariable<HeaderVariable, N>,
        hashes: &ArrayVariable<Bytes32Variable, N>,
        num_enabled: Variable,
    );

    fn hash_data_root<const N: usize>(
        &mut self,
        data_roots: &ArrayVariable<HashVariable, N>,
        num_enabled: Variable,
    ) -> Bytes32Variable;
}

impl<L: PlonkParameters<D>, const D: usize> CommitmentMethods for CircuitBuilder<L, D> {
    fn verify_sequential_header_chain<const N: usize>(
        &mut self,
        headers: &ArrayVariable<HeaderVariable, N>,
        hashes: &ArrayVariable<Bytes32Variable, N>,
        num_enabled: Variable,
    ) {
        // for i in 0..(N - 1) {
        //     self.assert_is_equal(hashes[i], headers[i + 1].parent_hash);
        // }
    }

    fn hash_data_root<const N: usize>(
        &mut self,
        data_roots: &ArrayVariable<HashVariable, N>,
        num_enabled: Variable,
    ) -> Bytes32Variable {
        todo!();
    }
}
