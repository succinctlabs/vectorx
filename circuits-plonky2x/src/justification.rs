use plonky2x::frontend::ecc::ed25519::curve::curve_types::{AffinePoint, Curve};
use plonky2x::prelude::{
    ArrayVariable, CircuitBuilder, CircuitVariable, GoldilocksField, PlonkParameters, RichField,
    Target, Variable, Witness, WitnessWrite,
};

pub struct HintSimpleJustification<const NUM_AUTHORITIES: usize> {}

// TODO: take in block hash and authority_set_id
// Return authority_set_signers and signed_precommits

pub trait GrandpaJustificationVerifier<L: PlonkParameters<D>, const D: usize, C: Curve> {
    fn verify_authority_set_commitment<const NUM_AUTHORITIES: usize>(
        &mut self,
        authority_set_commitment: Bytes32Variable,
        authority_set_signers: &ArrayVariable<AuthoritySetSignersVariable, NUM_AUTHORITIES>,
    );

    fn verify_simple_justification<const NUM_AUTHORITIES: usize>(
        &mut self,
        block: HeaderVariable,
        block_hash: Bytes32Variable,
        authority_set_id: U32Variable,
        authority_set_hash: Bytes32Variable,
        authority_set_signers: &ArrayVariable<AuthoritySetSignersVariable, NUM_AUTHORITIES>,
        signed_precommits: &ArrayVariable<PrecommitVariable, NUM_AUTHORITIES>,
    );
}
