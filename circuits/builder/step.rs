use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, PlonkParameters};

use super::justification::GrandpaJustificationVerifier;
use crate::step::StepCircuit;
use crate::subchain_verification::SubChainVerifier;

pub trait StepMethods<L: PlonkParameters<D>, const D: usize> {
    // Verify the justification from the current authority set on target block, and compute the
    // state and data merkle root commitments over the range [trusted_block + 1, target_block]
    // inclusive, and also return the verified target header hash.
    fn step<
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
    ) -> (Bytes32Variable, Bytes32Variable, Bytes32Variable)
    where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>;
}

impl<L: PlonkParameters<D>, const D: usize> StepMethods<L, D> for CircuitBuilder<L, D> {
    fn step<
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
    ) -> (Bytes32Variable, Bytes32Variable, Bytes32Variable)
    where
        <<L as PlonkParameters<D>>::Config as plonky2x::prelude::plonky2::plonk::config::GenericConfig<D>>::Hasher:
        plonky2x::prelude::plonky2::plonk::config::AlgebraicHasher<<L as PlonkParameters<D>>::Field>
    {
        let (target_header_hash, state_root_merkle_root, data_root_merkle_root) = self
            .verify_subchain::<StepCircuit<
            MAX_AUTHORITY_SET_SIZE,
            MAX_HEADER_SIZE,
            MAX_NUM_HEADERS,
        >, MAX_NUM_HEADERS>(
            trusted_block,
            trusted_header_hash,
            target_block,
        );

        self.verify_simple_justification::<MAX_AUTHORITY_SET_SIZE>(
            target_block,
            target_header_hash,
            authority_set_id,
            authority_set_hash,
        );

        (
            target_header_hash,
            state_root_merkle_root,
            data_root_merkle_root,
        )
    }
}

#[cfg(test)]
pub mod tests {}
