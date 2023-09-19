use plonky2x::frontend::ecc::ed25519::curve::curve_types::{AffinePoint, Curve};
use plonky2x::prelude::{
    ArrayVariable, CircuitBuilder, CircuitVariable, GoldilocksField, PlonkParameters, RichField,
    Target, Variable, Witness, WitnessWrite,
};

pub const NUM_AUTHORITIES: usize = 76;
pub const ENCODED_PRECOMMIT_LENGTH: usize = 53;

#[derive(Clone, Debug, CircuitVariable)]
pub struct PrecommitVariable<C: Curve> {
    pub precommit_message: EncodedPrecommitVariable,
    pub signature: EddsaSignatureVariable<C>,
    pub pub_key: AffinePointTarget<C>,
}

#[derive(Clone)]
pub struct AuthoritySetSignersVariable<C: Curve> {
    pub pub_keys: ArrayVariable<AffinePointTarget<C>, NUM_AUTHORITIES>, // Array of pub keys (in compressed form)
    pub weights: ArrayVariable<VariableG<u64>, NUM_AUTHORITIES>, // Array of weights.  These are u64s, but we assume that they are going to be within the golidlocks field.
    pub commitment: HashVariable,
    pub set_id: Variable,
}

pub struct FinalizedBlockVariable<C: Curve> {
    pub hash: HashVariable,
    pub num: Variable,
}

pub trait GrandpaJustificationVerifier<L: PlonkParameters<D>, const D: usize, C: Curve> {
    fn verify_authority_set_commitment(
        &mut self,
        authority_set_signers: &AuthoritySetSignersVariable<C>,
    );

    fn verify_justification(
        &mut self,
        signed_precommits: Vec<PrecommitVariable<C>>, // TODO what size is this
        authority_set_signers: &AuthoritySetSignersVariable<C>,
        finalized_block: &FinalizedBlockVariable,
    );
}
