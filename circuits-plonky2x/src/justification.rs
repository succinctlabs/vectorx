use plonky2x::frontend::ecc::ed25519::gadgets::verify::EDDSABatchVerify;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::{U32Variable, VariableStream};
use plonky2x::prelude::{
    ArrayVariable, BoolVariable, Bytes32Variable, BytesVariable, CircuitBuilder, PlonkParameters,
    Variable,
};
use plonky2x::utils::avail::justification::HintSimpleJustification;
use plonky2x::utils::avail::vars::{Curve, EDDSAPublicKeyVariable};

use crate::vars::*;

pub trait GrandpaJustificationVerifier {
    fn verify_authority_set_commitment<const NUM_AUTHORITIES: usize>(
        &mut self,
        num_active_authorities: Variable,
        authority_set_commitment: Bytes32Variable,
        authority_set_signers: &ArrayVariable<EDDSAPublicKeyVariable, NUM_AUTHORITIES>,
    );

    fn verify_simple_justification<const NUM_AUTHORITIES: usize>(
        &mut self,
        block_number: U32Variable,
        block_hash: Bytes32Variable,
        authority_set_id: U64Variable,
        authority_set_hash: Bytes32Variable,
    );
}

impl<L: PlonkParameters<D>, const D: usize> GrandpaJustificationVerifier for CircuitBuilder<L, D> {
    fn verify_authority_set_commitment<const NUM_AUTHORITIES: usize>(
        &mut self,
        _num_active_authorities: Variable,
        _authority_set_commitment: Bytes32Variable,
        _authority_set_signers: &ArrayVariable<EDDSAPublicKeyVariable, NUM_AUTHORITIES>,
    ) {
        todo!()
    }

    // This assumes
    fn verify_simple_justification<const NUM_AUTHORITIES: usize>(
        &mut self,
        block_number: U32Variable,
        _block_hash: Bytes32Variable,
        authority_set_id: U64Variable,
        _authority_set_hash: Bytes32Variable,
    ) {
        let mut input_stream = VariableStream::new();
        input_stream.write(&block_number);
        input_stream.write(&authority_set_id);
        let output_stream = self.hint(input_stream, HintSimpleJustification::<NUM_AUTHORITIES> {});

        let encoded_precommit = output_stream.read::<BytesVariable<ENCODED_PRECOMMIT_LENGTH>>(self);
        let validator_signed =
            output_stream.read::<ArrayVariable<BoolVariable, NUM_AUTHORITIES>>(self);
        let signatures =
            output_stream.read::<ArrayVariable<EDDSASignatureTarget<Curve>, NUM_AUTHORITIES>>(self);
        let pubkeys =
            output_stream.read::<ArrayVariable<EDDSAPublicKeyVariable, NUM_AUTHORITIES>>(self);
        // TODO: read `num_active_authorities` from output stream

        // TODO: call verify_authority_set_commitment

        // TODO: decode the encoded_precommit and ensure that it matches the block_hash, block_number, and authority_set_id

        // We verify the signatures of the validators on the encoded_precommit message.
        // `conditional_batch_eddsa_verify` doesn't assume all messages are the same, but in our case they are
        // and they are also constant length, so we can have `message_byte_lengths` be a constant array
        let message_byte_lengths =
            self.constant::<ArrayVariable<U32Variable, NUM_AUTHORITIES>>(vec![
                ENCODED_PRECOMMIT_LENGTH
                    as u32;
                NUM_AUTHORITIES
            ]);
        let messages = vec![encoded_precommit; NUM_AUTHORITIES];
        self.conditional_batch_eddsa_verify::<NUM_AUTHORITIES, ENCODED_PRECOMMIT_LENGTH>(
            validator_signed,
            message_byte_lengths,
            messages.into(),
            signatures,
            pubkeys,
        );

        // TODO: ensure that at least 2/3 signed based on the `num_active_authorities`
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use ethers::types::H256;
    use log::info;
    use plonky2x::prelude::{Bytes32Variable, DefaultBuilder};
    use plonky2x::utils::avail::fetch::RpcDataFetcher;
    use plonky2x::utils::avail::vars::SimpleJustificationData;
    use tokio::runtime::Runtime;

    use super::*;

    #[test]
    fn test_simple_justification() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        // There are only 7 authories in the 10,000-th block
        // But we set NUM_AUTHORITIES=10 so that we can test padding
        const BLOCK_NUMBER: u32 = 10000u32;
        const NUM_AUTHORITIES: usize = 7;

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
