use plonky2x::prelude::{Circuit, VerifiableFunction, DefaultBuilder, PlonkParameters, Bytes32Variable, BytesVariable, ArrayVariable};



#[derive(Debug, Clone, Serialize, Deserialize)]
struct GetOffchainInputs {
}

impl<L: PlonkParameters<D>, const D: usize> Hint<L, D> for GetOffchainInputs {
    fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let pub_input_hash = input_stream.read_value::<AvailHashTarget>();
        let provider = get_provider_from_env();
        let og_input = provider.get_hash_input(pub_input_hash);
        // Call all RPCs to get all the inputs necesary for step
        // spawn 50 tasks 
        // generate header proof for each 

        output_stream.write_value::<ProofWithPublicInputsVariable>(...)
        output_stream.write_value::<ArrayVariable<PrecommitVariable; QUORUM_SIZE>>(...)
        output_stream.write_value::<AuthoritySetSignersVariablet>(...)
        output_stream.write_value::<Bytes32Variable>(...)
    }
}

struct AvailStepEntrypoint {}

impl Circuit for AvailStepEntrypoint {
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
        let headHash = builder.read::<Bytes32Variable>();
        let updatedHeadHash = builder.read::<Bytes32Variable>();
        let dataRootsCommitment = builder.read::<Bytes32Variable>();
        let updatedDataRootsCommitment = builder.read::<Bytes32Variable>();
        let previousStateRoot = builder.read::<Bytes32Variable>();
        let newStateRoot = builder.read::<Bytes32Variable>();
        let authoritySetCommitment = builder.read::<Bytes32Variable>();
        let activeAuthoritySetId = builder.read::<BytesVariable<8>>();
        let head = builder.read::<BytesVariable<4>>();
        let updatedHeader = builder.read::<BytesVariable<4>>();

        let mut input_stream = VariableStream::new();
        input_stream.write(&public_inputs_hash);

        let hint = GetOffchainInputs { amount: 1 };
        let output_stream = builder.hint(input_stream, hint);
        let subchain_verification_proof = output_stream.read::<ProofWithPublicInputsVariable>(&mut builder);
        let signed_precommits = output_stream.read::<ArrayVariable<PrecommitVariable; QUORUM_SIZE>>(&mut builder);
        let authority_set_signers = output_stream.read::<AuthoritySetSignersVariable>(&mut builder);
        // TODO: I think we no longer need this
        let public_inputs_hash = output_stream.read::<Bytes32Variable>(&mut builder);
        builder.api.step(
            subchain_verification_proof,
            signed_precommits,
            authority_set_signers,
            public_inputs_hash,
        );

        builder.write::<BoolVariable>(builder._true());
    }
}

fn main() {
    VerifiableFunction::<AvailStepEntrypoint>::entrypoint();
}
