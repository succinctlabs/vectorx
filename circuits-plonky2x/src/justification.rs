use num::BigUint;
use plonky2x::frontend::hint::simple::hint::Hint;
use plonky2x::frontend::vars::{U32Variable, ValueStream, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    Field, PlonkParameters, RichField, Variable,
};
use serde::{Deserialize, Serialize};
use tokio::runtime::Runtime;

use crate::fetch::{RpcDataFetcher, SimpleJustificationData};
use crate::vars::*;

type SignatureValueType<F> = <EDDSASignatureTarget<Curve> as CircuitVariable>::ValueType<F>;

fn signature_to_value_type<F: RichField>(sig_bytes: &[u8]) -> SignatureValueType<F> {
    let sig_r = AffinePoint::new_from_compressed_point(&sig_bytes[0..32]);
    assert!(sig_r.is_valid());
    let sig_s_biguint = BigUint::from_bytes_le(&sig_bytes[32..64]);
    if sig_s_biguint.to_u32_digits().is_empty() {
        panic!("sig_s_biguint has 0 limbs which will cause problems down the line")
    }
    let sig_s = Ed25519Scalar::from_noncanonical_biguint(sig_s_biguint);
    SignatureValueType::<F> { r: sig_r, s: sig_s }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct HintSimpleJustification<const NUM_AUTHORITIES: usize> {}

impl<const NUM_AUTHORITIES: usize, L: PlonkParameters<D>, const D: usize> Hint<L, D>
    for HintSimpleJustification<NUM_AUTHORITIES>
{
    fn hint(&self, input_stream: &mut ValueStream<L, D>, output_stream: &mut ValueStream<L, D>) {
        let block_number = input_stream.read_value::<U32Variable>();
        let authority_set_id = input_stream.read_value::<U32Variable>();

        let rt = Runtime::new().expect("failed to create tokio runtime");
        let justification_data: SimpleJustificationData = rt.block_on(async {
            let data_fetcher = RpcDataFetcher::new().await;
            data_fetcher
                .get_simple_justification::<NUM_AUTHORITIES>(block_number)
                .await
        });

        if justification_data.authority_set_id != authority_set_id {
            panic!("Authority set id does not match");
        }

        let encoded_precommit = justification_data.signed_message;
        if encoded_precommit.len() != ENCODED_PRECOMMIT_LENGTH {
            panic!("Encoded precommit is not the correct length");
        }

        output_stream.write_value::<BytesVariable<ENCODED_PRECOMMIT_LENGTH>>(
            encoded_precommit.try_into().unwrap(),
        );
        output_stream.write_value::<ArrayVariable<BoolVariable, NUM_AUTHORITIES>>(
            justification_data.validator_signed,
        );
        output_stream.write_value::<ArrayVariable<EDDSASignatureTarget<Curve>, NUM_AUTHORITIES>>(
            justification_data
                .signatures
                .iter()
                .map(|x| signature_to_value_type::<L::Field>(x))
                .collect(),
        );
        output_stream.write_value::<ArrayVariable<EDDSAPublicKeyVariable, NUM_AUTHORITIES>>(
            justification_data.pubkeys,
        );
    }
}

// TODO: take in block hash and authority_set_id
// Return authority_set_signers and signed_precommits

pub trait GrandpaJustificationVerifier {
    fn verify_authority_set_commitment<const NUM_AUTHORITIES: usize>(
        &mut self,
        num_active_authorities: Variable,
        authority_set_commitment: Bytes32Variable,
        authority_set_signers: &ArrayVariable<EDDSAPublicKeyVariable, NUM_AUTHORITIES>,
    );

    fn verify_simple_justification<const NUM_AUTHORITIES: usize>(
        &mut self,
        block: HeaderVariable,
        block_hash: Bytes32Variable,
        authority_set_id: U32Variable,
        authority_set_hash: Bytes32Variable,
        // authority_set_signers: &ArrayVariable<AuthoritySetSignersVariable, NUM_AUTHORITIES>,
        // signed_precommits: &ArrayVariable<SignedPrecommitVariable, NUM_AUTHORITIES>,
    );
}

impl<L: PlonkParameters<D>, const D: usize> GrandpaJustificationVerifier for CircuitBuilder<L, D> {
    fn verify_authority_set_commitment<const NUM_AUTHORITIES: usize>(
        &mut self,
        num_active_authorities: Variable,
        authority_set_commitment: Bytes32Variable,
        authority_set_signers: &ArrayVariable<EDDSAPublicKeyVariable, NUM_AUTHORITIES>,
    ) {
    }

    fn verify_simple_justification<const NUM_AUTHORITIES: usize>(
        &mut self,
        block: HeaderVariable,
        block_hash: Bytes32Variable,
        authority_set_id: U32Variable,
        authority_set_hash: Bytes32Variable,
    ) {
        let mut input_stream = VariableStream::new();
        input_stream.write(&block.block_number);
        input_stream.write(&authority_set_id);
        let output_stream = self.hint(input_stream, HintSimpleJustification::<NUM_AUTHORITIES> {});
        let encoded_precommit = output_stream.read::<BytesVariable<ENCODED_PRECOMMIT_LENGTH>>(self);
        let validator_signed =
            output_stream.read::<ArrayVariable<BoolVariable, NUM_AUTHORITIES>>(self);
        let signatures =
            output_stream.read::<ArrayVariable<EDDSASignatureTarget<Curve>, NUM_AUTHORITIES>>(self);
        let pubkeys =
            output_stream.read::<ArrayVariable<EDDSAPublicKeyVariable, NUM_AUTHORITIES>>(self);

        // TODO: call verify_authority_set_commitment

        // TODO: decode the encoded_precommit and ensure that it matches the block_hash, block_number, and authority_set_id

        // TODO: verify the signatures

        // TODO: ensure that at least 2/3 signed based on the `num_active_authorities`
    }
}
