use async_trait::async_trait;
use ethers::types::U256;
use log::debug;
use plonky2x::frontend::curta::ec::point::{CompressedEdwardsY, CompressedEdwardsYVariable};
use plonky2x::frontend::ecc::curve25519::ed25519::eddsa::EDDSASignatureVariableValue;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{U32Variable, ValueStream, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, Field,
    PlonkParameters, Variable,
};
use serde::{Deserialize, Serialize};

use super::decoder::DecodingMethods;
use crate::consts::ENCODED_PRECOMMIT_LENGTH;
use crate::input::types::CircuitJustification;
use crate::input::{verify_signature, RpcDataFetcher};
use crate::vars::{JustificationStruct, JustificationVariable};

/// Fetch the simple justification for a block.
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

        let mut data_fetcher = RpcDataFetcher::new().await;
        let justification_data: CircuitJustification = data_fetcher
            .get_justification_from_block::<NUM_AUTHORITIES>(block_number)
            .await;

        if justification_data.authority_set_id != authority_set_id {
            panic!("Authority set id does not match");
        }

        let encoded_precommit = justification_data.signed_message;
        if encoded_precommit.len() != ENCODED_PRECOMMIT_LENGTH {
            panic!("Encoded precommit is not the correct length");
        }

        for i in 0..justification_data.num_authorities {
            // Skip if the validator didn't sign.
            if !justification_data.validator_signed[i] {
                continue;
            }
            verify_signature(
                justification_data.pubkeys[i].as_bytes(),
                &encoded_precommit,
                &justification_data.signatures[i],
            );
        }

        output_stream.write_value::<JustificationVariable<NUM_AUTHORITIES>>(JustificationStruct {
            encoded_precommit: encoded_precommit.try_into().unwrap(),
            validator_signed: justification_data.validator_signed,
            signatures: justification_data
                .signatures
                .iter()
                .map(|sig| EDDSASignatureVariableValue {
                    r: CompressedEdwardsY::from_slice(&sig[0..32]).unwrap(),
                    s: U256::from_little_endian(&sig[32..64]),
                })
                .collect(),
            pubkeys: justification_data.pubkeys,
            num_authorities: justification_data.num_authorities as u32,
        });
    }
}

pub trait GrandpaJustificationVerifier {
    /// Verify the authority set commitment of an authority set. This is the chained hash of the
    /// first num_active_authorities public keys.
    ///
    /// Specifically for a chained hash of 3 public keys, the chained hash takes the form:
    ///     SHA256(SHA256(SHA256(pubkey[0]) || pubkey[1]) || pubkey[2])
    fn verify_authority_set_commitment<const MAX_NUM_AUTHORITIES: usize>(
        &mut self,
        num_active_authorities: Variable,
        authority_set_commitment: Bytes32Variable,
        authority_set_signers: &ArrayVariable<CompressedEdwardsYVariable, MAX_NUM_AUTHORITIES>,
    );

    /// Verify the number of validators that signed is greater than or equal to the threshold.
    fn verify_voting_threshold<const MAX_NUM_AUTHORITIES: usize>(
        &mut self,
        num_active_authorities: U32Variable,
        validator_signed: &ArrayVariable<BoolVariable, MAX_NUM_AUTHORITIES>,
        threshold_numerator: U32Variable,
        threshold_denominator: U32Variable,
    );

    /// Verify a simple justification on a block from the specified authority set.
    ///
    /// Specifically, this verifies that:
    ///     1) Authority set commitment matches the authority set.
    ///     2) Specified precommit message matches the block #, authority set id, and block hash.
    ///     3) Signatures on the precommit message are valid from each validator marked as signed.
    ///     4) At least 2/3 of the validators have signed the precommit message.
    fn verify_simple_justification<const MAX_NUM_AUTHORITIES: usize>(
        &mut self,
        block_number: U32Variable,
        block_hash: Bytes32Variable,
        authority_set_id: U64Variable,
        authority_set_hash: Bytes32Variable,
    );
}

impl<L: PlonkParameters<D>, const D: usize> GrandpaJustificationVerifier for CircuitBuilder<L, D> {
    /// Verify the authority set commitment of an authority set. This is the chained hash of the
    /// first num_active_authorities public keys.
    ///
    /// Ex. For a chained hash of 3 public keys, the chained hash takes the form:
    ///     SHA256(SHA256(SHA256(pubkey[0]) || pubkey[1]) || pubkey[2])
    fn verify_authority_set_commitment<const MAX_NUM_AUTHORITIES: usize>(
        &mut self,
        num_active_authorities: Variable,
        authority_set_commitment: Bytes32Variable,
        authority_set_signers: &ArrayVariable<CompressedEdwardsYVariable, MAX_NUM_AUTHORITIES>,
    ) {
        let mut authority_enabled = self._true();

        let mut commitment_so_far = self.curta_sha256(&authority_set_signers[0].0.as_bytes());

        for i in 1..MAX_NUM_AUTHORITIES {
            let curr_idx = self.constant::<Variable>(L::Field::from_canonical_usize(i));
            let at_end = self.is_equal(curr_idx, num_active_authorities);
            let not_at_end = self.not(at_end);

            // Upon reaching the last validator, turn enabled to false to ensure that the commitment_so_far is not updated.
            // This is because the authority set commitment is the chained hash of the first num_active_authorities public keys.
            authority_enabled = self.and(authority_enabled, not_at_end);

            let mut input_to_hash = Vec::new();
            input_to_hash.extend_from_slice(&commitment_so_far.as_bytes());
            input_to_hash.extend_from_slice(&authority_set_signers[i].0.as_bytes());

            // Compute the chained hash of the authority set commitment.
            let chained_hash = self.curta_sha256(&input_to_hash);

            // Update the commitment_so_far if this authority is enabled.
            commitment_so_far = self.select(authority_enabled, chained_hash, commitment_so_far);
        }

        self.assert_is_equal(authority_set_commitment, commitment_so_far);
    }

    /// Verify the number of validators that signed is greater than or equal to the threshold.
    fn verify_voting_threshold<const MAX_NUM_AUTHORITIES: usize>(
        &mut self,
        num_active_authorities: U32Variable,
        validator_signed: &ArrayVariable<BoolVariable, MAX_NUM_AUTHORITIES>,
        threshold_numerator: U32Variable,
        threshold_denominator: U32Variable,
    ) {
        let true_v = self._true();
        let mut num_signed: U32Variable = self.zero();
        for i in 0..MAX_NUM_AUTHORITIES {
            // 1 if validator signed, 0 otherwise. Already range-checked (as a bool), so use unsafe.
            let val_signed_u32 =
                U32Variable::from_variables_unsafe(&[validator_signed[i].variable]);
            num_signed = self.add(num_signed, val_signed_u32);
        }

        let scaled_num_signed = self.mul(num_signed, threshold_denominator);
        let scaled_threshold = self.mul(num_active_authorities, threshold_numerator);

        // Verify that the number of validators that signed is greater than the threshold.
        let is_valid_num_signed = self.gt(scaled_num_signed, scaled_threshold);
        self.assert_is_equal(is_valid_num_signed, true_v);
    }

    /// Verify a simple justification on a block from the specified authority set.
    ///
    /// Specifically, this verifies that:
    ///     1) Authority set commitment matches the authority set.
    ///     2) Specified precommit message matches the block #, authority set id, and block hash.
    ///     3) Signatures on the precommit message are valid from each validator marked as signed.
    ///     4) At least 2/3 of the validators have signed the precommit message.
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

        let justification = output_stream.read::<JustificationVariable<MAX_NUM_AUTHORITIES>>(self);

        // Verify the authority set commitment is valid.
        self.verify_authority_set_commitment(
            justification.num_authorities.variable,
            authority_set_hash,
            &justification.pubkeys,
        );

        // Verify the correctness of the encoded_precommit message.
        let decoded_precommit = self.decode_precommit(justification.encoded_precommit);
        self.assert_is_equal(decoded_precommit.block_number, block_number);
        self.assert_is_equal(decoded_precommit.authority_set_id, authority_set_id);
        self.assert_is_equal(decoded_precommit.block_hash, block_hash);

        // Verify the signatures of the validators on the encoded_precommit message.
        // `curta_eddsa_verify_sigs_conditional` requires the message for each signature, but because
        // the message is the same, pass a constant array of the same message.
        let message_byte_lengths = self
            .constant::<ArrayVariable<U32Variable, MAX_NUM_AUTHORITIES>>(vec![
                ENCODED_PRECOMMIT_LENGTH
                    as u32;
                MAX_NUM_AUTHORITIES
            ]);
        let messages = vec![justification.encoded_precommit; MAX_NUM_AUTHORITIES];
        self.curta_eddsa_verify_sigs_conditional(
            justification.validator_signed.clone(),
            Some(message_byte_lengths),
            messages.into(),
            justification.signatures,
            justification.pubkeys,
        );

        // Verify at least 2/3 of the validators have signed the message.
        let two_v = self.constant::<U32Variable>(2u32);
        let three_v = self.constant::<U32Variable>(3u32);
        self.verify_voting_threshold(
            justification.num_authorities,
            &justification.validator_signed,
            two_v,
            three_v,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use plonky2x::prelude::{Bytes32Variable, DefaultBuilder};

    use super::*;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_verify_simple_justification() {
        env::set_var("RUST_LOG", "debug");
        dotenv::dotenv().ok();
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 8;
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

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut input = circuit.input();

        // target_block is an era end block in epoch 0 with 5 authorities.
        let target_block = 4321u32;
        let target_header = "c70877fed9ae5a040edb11e8800b3df53ec4c9ec67d07b5655a300ae11727dc1"
            .parse()
            .unwrap();
        let authority_set_id = 0u64;
        let authority_set_hash = "54eb3049b763a6a84c391d53ffb5e93515a171b2dbaaa6a900ec09e3b6bb8dfb"
            .parse()
            .unwrap();

        input.write::<U32Variable>(target_block);

        input.write::<Bytes32Variable>(target_header);

        input.write::<U64Variable>(authority_set_id);

        input.write::<Bytes32Variable>(authority_set_hash);

        log::debug!("Generating proof");
        let (proof, output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
    }
}
