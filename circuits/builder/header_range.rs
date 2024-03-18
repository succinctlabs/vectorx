use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters};

use super::justification::GrandpaJustificationVerifier;
use crate::builder::subchain_verification::SubChainVerifier;
use crate::header_range::HeaderRangeCircuit;
use crate::vars::SubchainVerificationVariable;

pub trait HeaderRangeMethods<L: PlonkParameters<D>, const D: usize> {
    // Verify the justification from the current authority set on target block, and compute the
    // state and data merkle root commitments over the range [trusted_block + 1, target_block]
    // inclusive, and also return the verified target header hash.
    fn prove_header_range<
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_HEADER_SIZE: usize,
        const MAX_NUM_HEADERS: usize,
    >(
        &mut self,
        trusted_block: U32Variable,
        trusted_header_hash: Bytes32Variable,
        authority_set_id: U64Variable,
        authority_set_hash: Bytes32Variable,
        target_block: U32Variable,
    ) -> SubchainVerificationVariable
    where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>;
}

impl<L: PlonkParameters<D>, const D: usize> HeaderRangeMethods<L, D> for CircuitBuilder<L, D> {
    fn prove_header_range<
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_HEADER_SIZE: usize,
        const MAX_NUM_HEADERS: usize,
    >(
        &mut self,
        trusted_block: U32Variable,
        trusted_header_hash: Bytes32Variable,
        authority_set_id: U64Variable,
        authority_set_hash: Bytes32Variable,
        target_block: U32Variable,
    ) -> SubchainVerificationVariable
    where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>
    {
        // Get the target_header_hash, state_root, and data_root over the range [trusted_block + 1, target_block].
        let subchain_output = self.verify_subchain::<HeaderRangeCircuit<
            MAX_AUTHORITY_SET_SIZE,
            MAX_HEADER_SIZE,
            MAX_NUM_HEADERS,
        >, MAX_NUM_HEADERS>(
            trusted_block, trusted_header_hash, target_block
        );

        self.verify_simple_justification::<MAX_AUTHORITY_SET_SIZE>(
            target_block,
            subchain_output.target_header_hash,
            authority_set_id,
            authority_set_hash,
        );

        subchain_output
    }
}

#[cfg(test)]
pub mod tests {}
