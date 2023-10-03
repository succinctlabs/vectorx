use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, CircuitBuilder, Field, PlonkParameters, Variable,
};
use plonky2x::utils::avail::HeaderVariable;

pub trait CommitmentMethods {
    fn get_enabled_array<const N: usize>(
        &mut self,
        num_enabled: Variable,
    ) -> ArrayVariable<BoolVariable, N>;

    fn verify_sequential_header_chain<const N: usize>(
        &mut self,
        headers: &ArrayVariable<HeaderVariable, N>,
        hashes: &ArrayVariable<Bytes32Variable, N>,
        enabled: &ArrayVariable<BoolVariable, N>,
    );

    fn hash_data_root<const N: usize>(
        &mut self,
        data_roots: &ArrayVariable<Bytes32Variable, N>,
        enabled: &ArrayVariable<BoolVariable, N>,
    ) -> Bytes32Variable;
}

impl<L: PlonkParameters<D>, const D: usize> CommitmentMethods for CircuitBuilder<L, D> {
    fn get_enabled_array<const N: usize>(
        &mut self,
        num_enabled: Variable,
    ) -> ArrayVariable<BoolVariable, N> {
        let mut leaves_enabled = Vec::new();
        let mut is_enabled = self.constant::<BoolVariable>(true);
        for i in 0..N {
            leaves_enabled.push(is_enabled);

            // Number of leaves included in the data commitment so far (including this leaf).
            let num_leaves_so_far =
                self.constant::<Variable>(L::Field::from_canonical_usize(i + 1));
            // If at the last_valid_leaf, must flip is_enabled to false.
            let is_last_valid_leaf = self.is_equal(num_enabled, num_leaves_so_far);
            let is_not_last_valid_leaf = self.not(is_last_valid_leaf);

            is_enabled = self.and(is_enabled, is_not_last_valid_leaf);
        }
        ArrayVariable::new(leaves_enabled)
    }

    fn verify_sequential_header_chain<const N: usize>(
        &mut self,
        headers: &ArrayVariable<HeaderVariable, N>,
        hashes: &ArrayVariable<Bytes32Variable, N>,
        enabled: &ArrayVariable<BoolVariable, N>,
    ) {
        let true_ = self._true();
        for i in 0..(N - 1) {
            let parent_hash_matches = self.is_equal(hashes[i], headers[i + 1].parent_hash);
            let is_enabled = enabled[i];
            let parent_hash_matches_or_is_enabled = self.or(parent_hash_matches, is_enabled);
            self.assert_is_equal(parent_hash_matches_or_is_enabled, true_);
        }
    }

    fn hash_data_root<const N: usize>(
        &mut self,
        leaves: &ArrayVariable<Bytes32Variable, N>,
        enabled: &ArrayVariable<BoolVariable, N>,
    ) -> Bytes32Variable {
        self.compute_root_from_leaves::<N, 32>(
            leaves.as_vec().iter().map(|x| x.0).collect(),
            enabled.as_vec(),
        )
    }
}
