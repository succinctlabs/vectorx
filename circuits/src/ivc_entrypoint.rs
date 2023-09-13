// Every block N
// generate_header_proof(N) -> header_proof_N
// generate_ivc(header_proof_N, ivc_{N-1}, base_case_flag)

// struct AvailIvcEntrypoint {}

// impl Circuit for AvailIvcEntrypoint {
//     fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
//         // get header from hint by calling RPC
//         let header_proof, header_fields = builder.api.get_header_fields(header_hash, header_bytes);

//         // get previous_ivc by calling RPC for "proof store"
//         let ivc_proof = builder.api.verify_header_ivc()

//         builder.write::<ivc_proof>(...);

//         let updatedHeadHash = builder.read::<Bytes32Variable>();
//         let dataRootsCommitment = builder.read::<Bytes32Variable>();
//         let updatedDataRootsCommitment = builder.read::<Bytes32Variable>();
//         let previousStateRoot = builder.read::<Bytes32Variable>();

//         let mut input_stream = VariableStream::new();
//         input_stream.write(&public_inputs_hash);

//         let hint = AddSome { amount: 1 };
//         let output_stream = builder.hint(input_stream, hint);
//         let pi_target = output_stream.read::<ProofWithPublicInputsTarget>(&mut builder);
//         // etc.

//         // CONVERT circuitvariable to step format

//         builder.api.step(subchain_verification_proof, pi_target);
//         builder.write::<BoolVariable>(builder._true());
//     }
// }

// fn main() {
//     VerifiableFunction::<AvailCircuit>::entrypoint();
// }
