use async_trait::async_trait;
use log::debug;
use num::traits::ToBytes;
use num::BigUint;
use plonky2x::frontend::ecc::ed25519::gadgets::curve::CircuitBuilderCurveGadget;
use plonky2x::frontend::ecc::ed25519::gadgets::verify::EDDSABatchVerify;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{U32Variable, ValueStream, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, BytesVariable, CircuitBuilder, CircuitVariable,
    Field, PlonkParameters, RichField, Variable,
};
use serde::{Deserialize, Serialize};

use super::decoder::DecodingMethods;
use crate::consts::ENCODED_PRECOMMIT_LENGTH;
use crate::input::types::SimpleJustificationData;
use crate::input::{verify_signature, RpcDataFetcher};
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
pub struct HintSimpleJustification<const NUM_AUTHORITIES: usize> {}

#[async_trait]
impl<const NUM_AUTHORITIES: usize, L: PlonkParameters<D>, const D: usize> AsyncHint<L, D>
    for HintSimpleJustification<NUM_AUTHORITIES>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let block_number = input_stream.read_value::<U32Variable>();
        let authority_set_id = input_stream.read_value::<U64Variable>();

        debug!(
            "HintSimpleJustification: downloading justification for block_number={} authority_set_id={}",
            block_number, authority_set_id
        );

        let data_fetcher = RpcDataFetcher::new().await;
        let justification_data: SimpleJustificationData = data_fetcher
            .get_simple_justification::<NUM_AUTHORITIES>(block_number)
            .await;

        if justification_data.authority_set_id != authority_set_id {
            panic!("Authority set id does not match");
        }

        let encoded_precommit = justification_data.signed_message;
        if encoded_precommit.len() != ENCODED_PRECOMMIT_LENGTH {
            panic!("Encoded precommit is not the correct length");
        }

        verify_signature(
            &justification_data.pubkeys[0].compress_point().to_le_bytes(),
            &encoded_precommit,
            &justification_data.signatures[0],
        );

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
        output_stream.write_value::<Variable>(L::Field::from_canonical_usize(
            justification_data.num_authorities,
        ));
    }
}

pub trait GrandpaJustificationVerifier {
    /// Verify the authority set commitment of an authority set. This is the chained hash of the first num_active_authorities public keys.
    /// Specifically, the chained hash takes the form: SHA256(SHA256(SHA256(pubkey[0]) || pubkey[1]) || pubkey[2])...
    fn verify_authority_set_commitment<const MAX_NUM_AUTHORITIES: usize>(
        &mut self,
        num_active_authorities: Variable,
        authority_set_commitment: Bytes32Variable,
        authority_set_signers: &ArrayVariable<AvailPubkeyVariable, MAX_NUM_AUTHORITIES>,
    );

    fn verify_voting_threshold<const MAX_NUM_AUTHORITIES: usize>(
        &mut self,
        num_active_authorities: Variable,
        validator_signed: &ArrayVariable<BoolVariable, MAX_NUM_AUTHORITIES>,
        threshold_numerator: Variable,
        threshold_denominator: Variable,
    );

    fn verify_simple_justification<const MAX_NUM_AUTHORITIES: usize>(
        &mut self,
        block_number: U32Variable,
        block_hash: Bytes32Variable,
        authority_set_id: U64Variable,
        authority_set_hash: Bytes32Variable,
    );
}

impl<L: PlonkParameters<D>, const D: usize> GrandpaJustificationVerifier for CircuitBuilder<L, D> {
    fn verify_authority_set_commitment<const MAX_NUM_AUTHORITIES: usize>(
        &mut self,
        num_active_authorities: Variable,
        authority_set_commitment: Bytes32Variable,
        authority_set_signers: &ArrayVariable<AvailPubkeyVariable, MAX_NUM_AUTHORITIES>,
    ) {
        let mut authority_enabled = self._true();

        let mut commitment_so_far = self.curta_sha256(&authority_set_signers[0].as_bytes());

        for i in 1..MAX_NUM_AUTHORITIES {
            let curr_idx = self.constant::<Variable>(L::Field::from_canonical_usize(i));
            let at_end = self.is_equal(curr_idx, num_active_authorities);
            let not_at_end = self.not(at_end);

            // Once reaching the last validator, turn enabled to false to ensure that the commitment_so_far is not updated.
            // This is because the authority set commitment is the chained hash of the first num_active_authorities public keys.
            authority_enabled = self.and(authority_enabled, not_at_end);

            let mut input_to_hash = Vec::new();
            input_to_hash.extend_from_slice(&commitment_so_far.as_bytes());
            input_to_hash.extend_from_slice(&authority_set_signers[i].as_bytes());

            // Compute the chained hash of the authority set commitment.
            let chained_hash = self.curta_sha256(&input_to_hash);

            // If we are before the end, update the commitment_so_far.
            commitment_so_far = self.select(authority_enabled, chained_hash, commitment_so_far);
        }

        self.assert_is_equal(authority_set_commitment, commitment_so_far);
    }

    fn verify_voting_threshold<const MAX_NUM_AUTHORITIES: usize>(
        &mut self,
        num_active_authorities: Variable,
        validator_signed: &ArrayVariable<BoolVariable, MAX_NUM_AUTHORITIES>,
        threshold_numerator: Variable,
        threshold_denominator: Variable,
    ) {
        let true_v = self._true();
        let mut num_signed: Variable = self.zero();
        for i in 0..MAX_NUM_AUTHORITIES {
            num_signed = self.add(num_signed, validator_signed[i].variable);
        }

        let scaled_num_signed = self.mul(num_signed, threshold_denominator);
        let scaled_threshold = self.mul(num_active_authorities, threshold_numerator);
        let is_valid_num_signed = self.gte(scaled_num_signed, scaled_threshold);
        self.assert_is_equal(is_valid_num_signed, true_v);
    }

    fn verify_simple_justification<const MAX_NUM_AUTHORITIES: usize>(
        &mut self,
        block_number: U32Variable,
        block_hash: Bytes32Variable,
        authority_set_id: U64Variable,
        authority_set_hash: Bytes32Variable,
    ) {
        let mut input_stream = VariableStream::new();
        input_stream.write(&block_number);
        input_stream.write(&authority_set_id);
        let output_stream = self.async_hint(
            input_stream,
            HintSimpleJustification::<MAX_NUM_AUTHORITIES> {},
        );

        let encoded_precommit = output_stream.read::<BytesVariable<ENCODED_PRECOMMIT_LENGTH>>(self);
        let validator_signed =
            output_stream.read::<ArrayVariable<BoolVariable, MAX_NUM_AUTHORITIES>>(self);
        let signatures = output_stream
            .read::<ArrayVariable<EDDSASignatureTarget<Curve>, MAX_NUM_AUTHORITIES>>(self);
        let pubkeys =
            output_stream.read::<ArrayVariable<EDDSAPublicKeyVariable, MAX_NUM_AUTHORITIES>>(self);
        let num_active_authorities = output_stream.read::<Variable>(self);

        // Compress the pubkeys from affine points to bytes.
        let compressed_pubkeys = ArrayVariable::<AvailPubkeyVariable, MAX_NUM_AUTHORITIES>::from(
            pubkeys
                .as_vec()
                .iter()
                .map(|x| self.compress_point(x).0)
                .collect::<Vec<Bytes32Variable>>(),
        );

        // Verify the authority set commitment is valid.
        self.verify_authority_set_commitment(
            num_active_authorities,
            authority_set_hash,
            &compressed_pubkeys,
        );

        // Verify the correctness of the encoded_precommit message.
        let decoded_precommit = self.decode_precommit(encoded_precommit);

        self.assert_is_equal(decoded_precommit.block_number, block_number);
        self.assert_is_equal(decoded_precommit.authority_set_id, authority_set_id);
        self.assert_is_equal(decoded_precommit.block_hash, block_hash);

        // We verify the signatures of the validators on the encoded_precommit message.
        // `conditional_batch_eddsa_verify` doesn't assume all messages are the same, but in our case they are
        // and they are also constant length, so we can have `message_byte_lengths` be a constant array
        let message_byte_lengths = self
            .constant::<ArrayVariable<U32Variable, MAX_NUM_AUTHORITIES>>(vec![
                ENCODED_PRECOMMIT_LENGTH
                    as u32;
                MAX_NUM_AUTHORITIES
            ]);
        let messages = vec![encoded_precommit; MAX_NUM_AUTHORITIES];
        self.conditional_batch_eddsa_verify::<MAX_NUM_AUTHORITIES, ENCODED_PRECOMMIT_LENGTH>(
            validator_signed.clone(),
            message_byte_lengths,
            messages.into(),
            signatures,
            pubkeys,
        );

        // Verify at least 2/3 of the validators have signed the message.
        let two_v = self.constant::<Variable>(L::Field::from_canonical_usize(2));
        let three_v = self.constant::<Variable>(L::Field::from_canonical_usize(3));
        self.verify_voting_threshold(num_active_authorities, &validator_signed, two_v, three_v)
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use ethers::types::H256;
    use log::info;
    use plonky2x::prelude::{Bytes32Variable, DefaultBuilder};
    use tokio::runtime::Runtime;

    use super::*;

    #[test]
    fn test_simple_justification() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        // There are only 7 authories in the 10,000-th block
        // But we set NUM_AUTHORITIES=10 so that we can test padding
        const BLOCK_NUMBER: u32 = 317857u32;
        const NUM_AUTHORITIES: usize = 80;

        let rt = Runtime::new().expect("failed to create tokio runtime");
        let justification_data: SimpleJustificationData = rt.block_on(async {
            let fetcher = RpcDataFetcher::new().await;
            fetcher
                .get_simple_justification::<NUM_AUTHORITIES>(BLOCK_NUMBER)
                .await
        });
        let fetched_authority_set_id = justification_data.authority_set_id;

        info!("Defining circuit");
        // Define the circuit
        let mut builder = DefaultBuilder::new();

        let block_number = builder.read::<U32Variable>();
        let block_hash = builder.read::<Bytes32Variable>();
        let authority_set_id = builder.read::<U64Variable>();
        let authority_set_hash = builder.read::<Bytes32Variable>();
        builder.verify_simple_justification::<NUM_AUTHORITIES>(
            block_number,
            block_hash,
            authority_set_id,
            authority_set_hash,
        );
        info!("Building circuit");
        let circuit = builder.build();

        let mut input = circuit.input();
        input.write::<U32Variable>(BLOCK_NUMBER);
        input.write::<Bytes32Variable>(H256::from([0u8; 32]));
        input.write::<U64Variable>(fetched_authority_set_id);
        input.write::<Bytes32Variable>(H256::from([0u8; 32])); // TODO: will have to be filled in with real thing

        info!("Generating proof");
        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);
    }
}
