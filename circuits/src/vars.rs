use std::fmt::Debug;

pub use plonky2x::frontend::ecc::ed25519::curve::curve_types::AffinePoint;
pub use plonky2x::frontend::ecc::ed25519::curve::ed25519::Ed25519;
pub use plonky2x::frontend::ecc::ed25519::field::ed25519_scalar::Ed25519Scalar;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::AffinePointTarget;
pub use plonky2x::frontend::ecc::ed25519::gadgets::eddsa::EDDSASignatureTarget;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    ArrayVariable, ByteVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    PlonkParameters, RichField, Variable,
};

use crate::consts::ENCODED_PRECOMMIT_LENGTH;

#[derive(Clone, Debug, CircuitVariable)]
#[value_name(EncodedHeader)]
pub struct EncodedHeaderVariable<const S: usize> {
    pub header_bytes: ArrayVariable<ByteVariable, S>,
    pub header_size: Variable,
}

/// The public key of the validator as a variable.
pub type AvailPubkeyVariable = Bytes32Variable;

#[derive(Clone, Debug, CircuitVariable)]
#[value_name(HeaderValueType)]
pub struct HeaderVariable {
    pub block_number: U32Variable,
    pub parent_hash: Bytes32Variable,
    pub state_root: Bytes32Variable,
    pub data_root: Bytes32Variable,
}

#[derive(Clone, Debug, CircuitVariable)]
pub struct PrecommitVariable {
    pub block_hash: Bytes32Variable,
    pub block_number: U32Variable,
    pub justification_round: U64Variable,
    pub authority_set_id: U64Variable,
}

pub type Curve = Ed25519;
pub type EDDSAPublicKeyVariable = AffinePointTarget<Curve>;

#[derive(Clone, Debug, CircuitVariable)]
pub struct SignedPrecommitVariable {
    pub encoded_precommit_message: BytesVariable<ENCODED_PRECOMMIT_LENGTH>,
    pub signature: EDDSASignatureTarget<Curve>,
}

#[derive(Clone)]
pub struct AuthoritySetSignerVariable {
    pub pub_keys: EDDSAPublicKeyVariable, // Array of pub keys (in compressed form)
    pub weights: U64Variable, // Array of weights.  These are u64s, but we assume that they are going to be within the golidlocks field.
}
