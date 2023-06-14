use plonky2lib_succinct::ed25519::curve::curve_types::Curve;
use plonky2lib_succinct::hash_functions::blake2b::make_blake2b_circuit;
use plonky2::{iop::target::{Target, BoolTarget}, hash::hash_types::RichField, plonk::{circuit_builder::CircuitBuilder}};
use plonky2_field::extension::Extendable;
use crate::{decoder::CircuitBuilderHeaderDecoder, utils::{QUORUM_SIZE, AvailHashTarget, EncodedHeaderTarget, CircuitBuilderUtils}};
use crate::justification::{CircuitBuilderGrandpaJustificationVerifier, PrecommitTarget, AuthoritySetSignersTarget, FinalizedBlockTarget};
use crate::utils::{MAX_HEADER_SIZE, HASH_SIZE, MAX_NUM_HEADERS_PER_STEP};

pub struct VerifySubchainTarget {
    pub head_block_hash: AvailHashTarget,   // The input is a vector of bits (in BE bit order)
    pub head_block_num: Target,
    pub encoded_headers: Vec<EncodedHeaderTarget>,
}

pub trait CircuitBuilderStep<C: Curve> {
    fn step(
        &mut self,
        subchain: &VerifySubchainTarget,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget,
    );
}

impl<F: RichField + Extendable<D>, const D: usize, C: Curve> CircuitBuilderStep<C> for CircuitBuilder<F, D> {
    fn step(
        &mut self,
        subchain: &VerifySubchainTarget,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget,
    ) {
        assert!(subchain.encoded_headers.len() <= MAX_NUM_HEADERS_PER_STEP);

        // We plan to store the the calculated blake2b hash (in bits) in calculated_hashes
        let mut calculated_hashes: Vec<Vec<BoolTarget>> = Vec::new();
        let mut decoded_block_nums = Vec::new();
        for i in 0 .. subchain.encoded_headers.len() {

            // Get the decoded_header object to retrieve the block numbers and parent hashes
            let decoded_header = self.decode_header(
                &subchain.encoded_headers[i],
            );

            println!("len of decoded_header.state_root.0 is {:?}", decoded_header.state_root.0.len());
            self.register_public_inputs(&decoded_header.state_root.0);

            // Verify that the previous calcualted block hash is equal to the decoded parent hash
            for j in 0 .. HASH_SIZE {
                let mut bits = self.split_le(decoded_header.parent_hash.0[j], 8);

                // Needs to be in bit big endian order for the blake2b verification circuit
                bits.reverse();
                for k in 0..8 {
                    if i == 0 {
                        let mut head_block_bits = self.split_le(subchain.head_block_hash.0[j], 8);
                        head_block_bits.reverse();
                        // For the first header in the subchain, verify equality to the head block hash public input.
                        self.connect(head_block_bits[k].target, bits[k].target);
                    } else {
                        // For other headers, verify equality to the previous block's calculated header hash
                        self.connect(calculated_hashes[i-1][j*8+k].target, bits[k].target);
                    }
                }
            }

            // Calculate the hash for the current header
            let hash_circuit = make_blake2b_circuit(
                self,
                MAX_HEADER_SIZE * 8,
                HASH_SIZE
            );

            // Input the encoded header bytes into the hasher
            for j in 0..MAX_HEADER_SIZE {
                // Need to split the bytes into bits
                let mut bits = self.split_le(subchain.encoded_headers[i].header_bytes[j], 8);

                // Needs to be in bit big endian order for the EDDSA verification circuit
                bits.reverse();
                for (k, bit) in bits.iter().enumerate().take(8){
                    self.connect(hash_circuit.message[j*8+k].target, bit.target);
                }
            }

            self.connect(hash_circuit.message_len, subchain.encoded_headers[i].header_size);

            calculated_hashes.push(hash_circuit.digest.clone());

            // Convert hash digest into bytes
            for bits in hash_circuit.digest.chunks(8) {
                // These bits are in big endian order
                let byte = self.le_sum(bits.iter().rev());
                self.register_public_input(byte);
            }

            // Verify that the block numbers are sequential
            let one = self.one();
            if i == 0 {
                let expected_block_num = self.add(subchain.head_block_num, one);
                self.connect(expected_block_num, decoded_header.block_number);
            } else {
                let expected_block_num = self.add(decoded_block_nums[i-1], one);
                self.connect(expected_block_num, decoded_header.block_number);
            }

            decoded_block_nums.push(decoded_header.block_number);
        }

        let last_calculated_hash = calculated_hashes.last().unwrap();
        let mut last_calculated_hash_bytes = Vec::new();
        // Convert the last calculated hash into bytes
        // The bits in the calculated hash are in bit big endian format
        for i in 0 .. HASH_SIZE {
            last_calculated_hash_bytes.push(self.le_sum(last_calculated_hash[i*8..i*8+8].to_vec().iter().rev()));
        }

        // Now verify the grandpa justification
        self.verify_justification(
            signed_precommits,
            authority_set_signers,
            &FinalizedBlockTarget {
                num: *decoded_block_nums.last().unwrap(),
                hash: AvailHashTarget(last_calculated_hash_bytes.try_into().unwrap()),
            },
        );
    }
}

pub struct StepTarget<C: Curve> {
    subchain_target: VerifySubchainTarget,
    precommits: [PrecommitTarget<C>; QUORUM_SIZE],
    authority_set: AuthoritySetSignersTarget,
}

pub fn make_step_circuit<F: RichField + Extendable<D>, const D: usize, C: Curve>(builder: &mut CircuitBuilder::<F, D>) -> StepTarget<C>{
    let head_block_hash_target = builder.add_virtual_avail_hash_target_safe(true);

    let head_block_num_target = builder.add_virtual_target();
    builder.register_public_input(head_block_num_target);

    let mut header_targets = Vec::new();
    for _i in 0..MAX_NUM_HEADERS_PER_STEP {
        header_targets.push(
            builder.add_virtual_encoded_header_target_safe()
        );
    }

    let mut precommit_targets = Vec::new();
    for _i in 0..QUORUM_SIZE {
        precommit_targets.push(builder.add_virtual_precommit_target_safe());
    }

    let authority_set = <CircuitBuilder<F, D> as CircuitBuilderGrandpaJustificationVerifier<C>>::add_virtual_authority_set_signers_target_safe(builder);

    let verify_subchain_target = VerifySubchainTarget {
        head_block_hash: head_block_hash_target,
        head_block_num: head_block_num_target,
        encoded_headers: header_targets,
    };

    builder.step(
        &verify_subchain_target,
        precommit_targets.clone(),
        &authority_set,
    );

    StepTarget{
        subchain_target: verify_subchain_target,
        precommits: precommit_targets.try_into().unwrap(),
        authority_set,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use anyhow::Result;
    use log::Level;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2::plonk::prover::prove;
    use plonky2::util::timing::TimingTree;
    use plonky2_field::extension::Extendable;
    use plonky2_field::types::Field;
    use plonky2lib_succinct::ed25519::curve::ed25519::Ed25519;

    use crate::plonky2_config::PoseidonBN128GoldilocksConfig;
    use crate::step::make_step_circuit;
    use crate::utils::{QUORUM_SIZE, WitnessAvailHash, WitnessEncodedHeader};
    use crate::utils::tests::{
        BLOCK_530508_PARENT_HASH,
        BLOCK_530508_HEADER,
        BLOCK_530509_HEADER,
        BLOCK_530510_HEADER,
        BLOCK_530511_HEADER,
        BLOCK_530512_HEADER,
        BLOCK_530513_HEADER,
        BLOCK_530514_HEADER,
        BLOCK_530515_HEADER,
        BLOCK_530516_HEADER,
        BLOCK_530517_HEADER,
        BLOCK_530518_PARENT_HASH,
        BLOCK_530518_HEADER,
        BLOCK_530519_HEADER,
        BLOCK_530520_HEADER,
        BLOCK_530521_HEADER,
        BLOCK_530522_HEADER,
        BLOCK_530523_PARENT_HASH,
        BLOCK_530523_HEADER,
        BLOCK_530524_HEADER,
        BLOCK_530525_HEADER,
        BLOCK_530526_PARENT_HASH,
        BLOCK_530526_HEADER,
        BLOCK_530527_HEADER,
        BLOCK_530527_AUTHORITY_SET_ID,
        BLOCK_530527_PARENT_HASH,
        BLOCK_530527_PRECOMMIT_MESSAGE,
        BLOCK_530527_AUTHORITY_SIGS,
        BLOCK_530527_AUTHORITY_SET, BLOCK_530527_PUB_KEY_INDICES, BLOCK_530527_AUTHORITY_SET_COMMITMENT,
    };
    use crate::justification::tests::{set_precommits_pw, set_authority_set_pw};

    fn gen_step_proof<F: RichField + Extendable<D>, C: GenericConfig<D, F = F>, const D: usize>(
        cd: &CircuitData<F, C, D>,
        pw: &PartialWitness<F>,
    ) -> ProofWithPublicInputs<F, C, D> {
        let mut timing = TimingTree::new("step proof gen", Level::Info);
        let proof = prove::<F, C, D>(&cd.prover_only, &cd.common, pw.clone(), &mut timing);
        timing.print();

        proof.unwrap()
    }

    fn test_step(
        headers: Vec<Vec<u8>>,
        head_block_hash: Vec<u8>,
        head_block_num: u64,

        authority_set_id: u64,
        precommit_message: Vec<u8>,
        signatures: Vec<Vec<u8>>,

        pub_key_indices: Vec<usize>,
        authority_set: Vec<Vec<u8>>,
        authority_set_commitment: Vec<u8>,
    ) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type Curve = Ed25519;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let mut pw: PartialWitness<F> = PartialWitness::new();

        let step_target = make_step_circuit::<F, D, Curve>(&mut builder);

        pw.set_avail_hash_target(&step_target.subchain_target.head_block_hash, &(head_block_hash.try_into().unwrap()));
        pw.set_target(step_target.subchain_target.head_block_num, F::from_canonical_u64(head_block_num));
        for (i, header) in headers.iter().enumerate() {
            pw.set_encoded_header_target(&step_target.subchain_target.encoded_headers[i], header.clone());
        }

        set_precommits_pw::<F, D, Curve>(
            &mut pw,
            step_target.precommits.to_vec(),
            (0..QUORUM_SIZE).map(|_| precommit_message.clone().to_vec()).collect::<Vec<_>>(),
            signatures,
            pub_key_indices,
            authority_set.clone(),
        );

        set_authority_set_pw::<F, D, Curve>(
            &mut pw,
            &step_target.authority_set,
            authority_set,
            authority_set_id,
            authority_set_commitment,
        );

        let data = builder.build();
        let proof = gen_step_proof::<F, C, D>(&data, &pw);
        data.verify(proof)
    }

    #[test]
    fn test_verify_headers_one() -> Result<()> {
        let headers = vec![BLOCK_530527_HEADER.to_vec()];
        let head_block_hash = hex::decode(BLOCK_530527_PARENT_HASH).unwrap();
        test_step(
            headers,
            head_block_hash,
            530526,
            BLOCK_530527_AUTHORITY_SET_ID,
            BLOCK_530527_PRECOMMIT_MESSAGE.to_vec(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_PUB_KEY_INDICES.to_vec(),
            BLOCK_530527_AUTHORITY_SET.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            hex::decode(BLOCK_530527_AUTHORITY_SET_COMMITMENT).unwrap(),
        )
    }

    #[test]
    fn test_verify_headers_two() -> Result<()> {
        let headers = vec![BLOCK_530526_HEADER.to_vec(), BLOCK_530527_HEADER.to_vec()];
        let head_block_hash = hex::decode(BLOCK_530526_PARENT_HASH).unwrap();
        test_step(
            headers,
            head_block_hash,
            530525,
            BLOCK_530527_AUTHORITY_SET_ID,
            BLOCK_530527_PRECOMMIT_MESSAGE.to_vec(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_PUB_KEY_INDICES.to_vec(),
            BLOCK_530527_AUTHORITY_SET.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            hex::decode(BLOCK_530527_AUTHORITY_SET_COMMITMENT).unwrap(),
        )
    }

    #[test]
    fn test_verify_headers_five() -> Result<()> {
        let headers = vec![
            BLOCK_530523_HEADER.to_vec(),
            BLOCK_530524_HEADER.to_vec(),
            BLOCK_530525_HEADER.to_vec(),
            BLOCK_530526_HEADER.to_vec(),
            BLOCK_530527_HEADER.to_vec(),
        ];
        let head_block_hash = hex::decode(BLOCK_530523_PARENT_HASH).unwrap();
        test_step(
            headers,
            head_block_hash,
            530522,
            BLOCK_530527_AUTHORITY_SET_ID,
            BLOCK_530527_PRECOMMIT_MESSAGE.to_vec(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_PUB_KEY_INDICES.to_vec(),
            BLOCK_530527_AUTHORITY_SET.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            hex::decode(BLOCK_530527_AUTHORITY_SET_COMMITMENT).unwrap(),
        )
    }

    #[test]
    fn test_verify_headers_ten() -> Result<()> {
        let headers = vec![
            BLOCK_530518_HEADER.to_vec(),
            BLOCK_530519_HEADER.to_vec(),
            BLOCK_530520_HEADER.to_vec(),
            BLOCK_530521_HEADER.to_vec(),
            BLOCK_530522_HEADER.to_vec(),
            BLOCK_530523_HEADER.to_vec(),
            BLOCK_530524_HEADER.to_vec(),
            BLOCK_530525_HEADER.to_vec(),
            BLOCK_530526_HEADER.to_vec(),
            BLOCK_530527_HEADER.to_vec(),
        ];
        let head_block_hash = hex::decode(BLOCK_530518_PARENT_HASH).unwrap();
        test_step(
            headers,
            head_block_hash,
            530517,
            BLOCK_530527_AUTHORITY_SET_ID,
            BLOCK_530527_PRECOMMIT_MESSAGE.to_vec(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_PUB_KEY_INDICES.to_vec(),
            BLOCK_530527_AUTHORITY_SET.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            hex::decode(BLOCK_530527_AUTHORITY_SET_COMMITMENT).unwrap(),
        )
    }

    #[test]
    fn test_verify_headers_twenty() -> Result<()> {
        let headers = vec![
            BLOCK_530508_HEADER.to_vec(),
            BLOCK_530509_HEADER.to_vec(),
            BLOCK_530510_HEADER.to_vec(),
            BLOCK_530511_HEADER.to_vec(),
            BLOCK_530512_HEADER.to_vec(),
            BLOCK_530513_HEADER.to_vec(),
            BLOCK_530514_HEADER.to_vec(),
            BLOCK_530515_HEADER.to_vec(),
            BLOCK_530516_HEADER.to_vec(),
            BLOCK_530517_HEADER.to_vec(),
            BLOCK_530518_HEADER.to_vec(),
            BLOCK_530519_HEADER.to_vec(),
            BLOCK_530520_HEADER.to_vec(),
            BLOCK_530521_HEADER.to_vec(),
            BLOCK_530522_HEADER.to_vec(),
            BLOCK_530523_HEADER.to_vec(),
            BLOCK_530524_HEADER.to_vec(),
            BLOCK_530525_HEADER.to_vec(),
            BLOCK_530526_HEADER.to_vec(),
            BLOCK_530527_HEADER.to_vec(),
        ];
        let head_block_hash = hex::decode(BLOCK_530508_PARENT_HASH).unwrap();
        test_step(
            headers,
            head_block_hash,
            530507,
            BLOCK_530527_AUTHORITY_SET_ID,
            BLOCK_530527_PRECOMMIT_MESSAGE.to_vec(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_PUB_KEY_INDICES.to_vec(),
            BLOCK_530527_AUTHORITY_SET.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            hex::decode(BLOCK_530527_AUTHORITY_SET_COMMITMENT).unwrap(),
        )
    }

    #[test]
    fn test_recursive_verify_step() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type Curve = Ed25519;

        let headers = vec![
            BLOCK_530508_HEADER.to_vec(),
            BLOCK_530509_HEADER.to_vec(),
            BLOCK_530510_HEADER.to_vec(),
            BLOCK_530511_HEADER.to_vec(),
            BLOCK_530512_HEADER.to_vec(),
            BLOCK_530513_HEADER.to_vec(),
            BLOCK_530514_HEADER.to_vec(),
            BLOCK_530515_HEADER.to_vec(),
            BLOCK_530516_HEADER.to_vec(),
            BLOCK_530517_HEADER.to_vec(),
            BLOCK_530518_HEADER.to_vec(),
            BLOCK_530519_HEADER.to_vec(),
            BLOCK_530520_HEADER.to_vec(),
            BLOCK_530521_HEADER.to_vec(),
            BLOCK_530522_HEADER.to_vec(),
            BLOCK_530523_HEADER.to_vec(),
            BLOCK_530524_HEADER.to_vec(),
            BLOCK_530525_HEADER.to_vec(),
            BLOCK_530526_HEADER.to_vec(),
            BLOCK_530527_HEADER.to_vec(),
        ];
        let head_block_hash = hex::decode(BLOCK_530508_PARENT_HASH).unwrap();
        let head_block_num = 530507;

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let mut builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let mut pw: PartialWitness<F> = PartialWitness::new();

        let step_target = make_step_circuit::<F, D, Curve>(&mut builder);

        pw.set_avail_hash_target(&step_target.subchain_target.head_block_hash, &(head_block_hash.try_into().unwrap()));
        pw.set_target(step_target.subchain_target.head_block_num, F::from_canonical_u64(head_block_num));
        for (i, header) in headers.iter().enumerate() {
            pw.set_encoded_header_target(&step_target.subchain_target.encoded_headers[i], header.clone());
        }

        set_precommits_pw::<F, D, Curve>(
            &mut pw,
            step_target.precommits.to_vec(),
            (0..QUORUM_SIZE).map(|_| BLOCK_530527_PRECOMMIT_MESSAGE.clone().to_vec()).collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_SIGS.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_PUB_KEY_INDICES.to_vec(),
            BLOCK_530527_AUTHORITY_SET.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
        );

        set_authority_set_pw::<F, D, Curve>(
            &mut pw,
            &step_target.authority_set,
            BLOCK_530527_AUTHORITY_SET.iter().map(|s| hex::decode(s).unwrap()).collect::<Vec<_>>(),
            BLOCK_530527_AUTHORITY_SET_ID,
            hex::decode(BLOCK_530527_AUTHORITY_SET_COMMITMENT).unwrap(),
        );

        let inner_data = builder.build();
        let inner_proof = gen_step_proof::<F, C, D>(&inner_data, &pw);
        inner_data.verify(inner_proof.clone()).unwrap();

        println!("inner circuit digest is {:?}", inner_data.verifier_only.circuit_digest);

        let mut outer_builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_ecc_config());
        let outer_proof_target = outer_builder.add_virtual_proof_with_pis(&inner_data.common);
        let outer_verifier_data = outer_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
        outer_builder.verify_proof::<C>(&outer_proof_target, &outer_verifier_data, &inner_data.common);
        outer_builder.register_public_inputs(&outer_proof_target.public_inputs);
        outer_builder.register_public_inputs(&outer_verifier_data.circuit_digest.elements);

        let outer_data = outer_builder.build::<PoseidonBN128GoldilocksConfig>();

        let mut outer_pw = PartialWitness::new();
        outer_pw.set_proof_with_pis_target(&outer_proof_target, &inner_proof);
        outer_pw.set_verifier_data_target(&outer_verifier_data, &inner_data.verifier_only);

        let outer_proof = outer_data.prove(outer_pw).unwrap();
        let ret = outer_data.verify(outer_proof.clone());

        for gate in outer_data.common.gates.iter() {
            println!("outer circuit: gate is {:?}", gate);
        }

        let outer_common_circuit_data_serialized = serde_json::to_string(&outer_data.common).unwrap();
        fs::write("step_recursive.common_circuit_data.json", outer_common_circuit_data_serialized)
            .expect("Unable to write file");

        let outer_verifier_only_circuit_data_serialized = serde_json::to_string(&outer_data.verifier_only).unwrap();
        fs::write(
            "step_recursive.verifier_only_circuit_data.json",
            outer_verifier_only_circuit_data_serialized,
        )
        .expect("Unable to write file");

        let outer_proof_serialized = serde_json::to_string(&outer_proof).unwrap();
        fs::write("step_recursive.proof_with_public_inputs.json", outer_proof_serialized).expect("Unable to write file");

        ret
    }
}