use plonky2lib_succinct::ed25519::curve::curve_types::Curve;
use plonky2lib_succinct::hash_functions::blake2b::make_blake2b_circuit;
use plonky2::{iop::target::{Target, BoolTarget}, hash::hash_types::RichField, plonk::{circuit_builder::CircuitBuilder}};
use plonky2_field::extension::Extendable;
use crate::{decoder::CircuitBuilderHeaderDecoder, utils::{QUORUM_SIZE, AvailHashTarget, EncodedHeaderTarget, CircuitBuilderUtils}};
use crate::justification::{CircuitBuilderGrandpaJustificationVerifier, PrecommitTarget, AuthoritySetSignersTarget, FinalizedBlockTarget};
use crate::utils::{MAX_HEADER_SIZE, HASH_SIZE, MAX_NUM_HEADERS_PER_STEP};

#[derive(Clone)]
pub struct VerifySubchainTarget {
    pub head_block_hash: AvailHashTarget,   // The input is a vector of bits (in BE bit order)
    pub head_block_num: Target,             // Should be a 32-bit unsigned integer
    pub encoded_headers: Vec<EncodedHeaderTarget>,
}

pub trait CircuitBuilderStep<C: Curve> {
    fn step(
        &mut self,
        subchain: &VerifySubchainTarget,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget,
        public_inputs_hash: &AvailHashTarget,
    );
}

impl<F: RichField + Extendable<D>, const D: usize, C: Curve> CircuitBuilderStep<C> for CircuitBuilder<F, D> {
    fn step(
        &mut self,
        subchain: &VerifySubchainTarget,
        signed_precommits: Vec<PrecommitTarget<C>>,
        authority_set_signers: &AuthoritySetSignersTarget,
        public_inputs_hash: &AvailHashTarget,
    ) {
        assert!(subchain.encoded_headers.len() <= MAX_NUM_HEADERS_PER_STEP);

        // The public inputs are 1356 bytes long (for 20 headers);
        // Need to store each byte as BE bits
        let mut public_inputs_hash_input = Vec::new();

        // Input the head hash into the public inputs hasher
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(subchain.head_block_hash.0[i], 8);

            // Needs to be in bit big endian order for the blake2b verification circuit
            bits.reverse();
            public_inputs_hash_input.append(&mut bits);
        }

        // Input the head number into the hasher
        let mut head_block_num_bits = self.split_le(subchain.head_block_num, 32);
        head_block_num_bits.reverse();
        public_inputs_hash_input.append(&mut head_block_num_bits);

        // Input the validator commitment into the hasher
        for i in 0..HASH_SIZE {
            let mut bits = self.split_le(authority_set_signers.commitment.0[i], 8);
            bits.reverse();
            public_inputs_hash_input.append(&mut bits);
        }

        // Input the validator set id into the hasher
        let mut set_id_bits = self.split_le(authority_set_signers.set_id, 64);
        set_id_bits.reverse();
        public_inputs_hash_input.append(&mut set_id_bits);

        // We plan to store the the calculated blake2b hash (in bits) in calculated_hashes
        let mut calculated_hashes: Vec<Vec<BoolTarget>> = Vec::new();
        let mut decoded_block_nums = Vec::new();
        for i in 0 .. subchain.encoded_headers.len() {

            // Get the decoded_header object to retrieve the block numbers and parent hashes
            let decoded_header = self.decode_header(
                &subchain.encoded_headers[i],
            );

            for j in 0..HASH_SIZE {
                let mut bits = self.split_le(decoded_header.state_root.0[j], 8);
                bits.reverse();
                public_inputs_hash_input.append(&mut bits);
            }

            // Verify that the previous calculated block hash is equal to the decoded parent hash
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
                public_inputs_hash_input.append(&mut bits.to_vec());
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

        // The input digest is 1356 bytes (for 20 headers).  Need to pad that so that the result
        // is divisible by CHUNK_128_BYTES.  That result is 1408 bytes
        let public_inputs_hash_circuit = make_blake2b_circuit(
            self,
            512 * 8,
            HASH_SIZE,
        );

        for (i, bit) in public_inputs_hash_input.iter().enumerate() {
            self.connect(bit.target, public_inputs_hash_circuit.message[i].target);
        }

        // Add the padding
        let zero = self.zero();
        for i in public_inputs_hash_input.len() .. 512 * 8 {
            self.connect(zero, public_inputs_hash_circuit.message[i].target);
        }

        let public_inputs_input_size = self.constant(F::from_canonical_usize(public_inputs_hash_input.len() / 8));
        self.connect(public_inputs_hash_circuit.message_len, public_inputs_input_size);

        // Verify that the public input hash matches
        for i in 0 .. HASH_SIZE {
            let mut bits = self.split_le(public_inputs_hash.0[i], 8);

            // Needs to be in bit big endian order for the BLAKE2B circuit
            bits.reverse();
            for (j, bit) in bits.iter().enumerate().take(8) {
                self.connect(public_inputs_hash_circuit.digest[i*8+j].target, bit.target);
            }
        }
    }
}

#[derive(Clone)]
pub struct StepTarget<C: Curve> {
    pub subchain_target: VerifySubchainTarget,
    pub precommits: [PrecommitTarget<C>; QUORUM_SIZE],
    pub authority_set: AuthoritySetSignersTarget,
    pub public_inputs_hash: AvailHashTarget,
}

pub fn make_step_circuit<F: RichField + Extendable<D>, const D: usize, C: Curve>(builder: &mut CircuitBuilder::<F, D>) -> StepTarget<C>{
    let head_block_hash_target = builder.add_virtual_avail_hash_target_safe(false);

    let head_block_num_target = builder.add_virtual_target();
    // The head block number is a 32 bit number
    builder.range_check(head_block_num_target, 32);

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

    let public_inputs_hash = builder.add_virtual_avail_hash_target_safe(true);

    builder.step(
        &verify_subchain_target,
        precommit_targets.clone(),
        &authority_set,
        &public_inputs_hash,
    );

    StepTarget{
        subchain_target: verify_subchain_target,
        precommits: precommit_targets.try_into().unwrap(),
        authority_set,
        public_inputs_hash,
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
    use plonky2_field::types::{Field, PrimeField64};
    use plonky2lib_succinct::ed25519::curve::ed25519::Ed25519;

    use crate::justification::{set_precommits_pw, set_authority_set_pw};
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
        BLOCK_530527_AUTHORITY_SET, BLOCK_530527_PUB_KEY_INDICES, BLOCK_530527_AUTHORITY_SET_COMMITMENT, BLOCK_530527_PUBLIC_INPUTS_HASH,
    };

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

        let public_inputs_hash = hex::decode(BLOCK_530527_PUBLIC_INPUTS_HASH).unwrap();

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

        pw.set_avail_hash_target(&step_target.public_inputs_hash, &(public_inputs_hash.try_into().unwrap()));

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

        let mut outer_builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let outer_proof_target = outer_builder.add_virtual_proof_with_pis(&inner_data.common);
        let outer_verifier_data = outer_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
        outer_builder.verify_proof::<C>(&outer_proof_target, &outer_verifier_data, &inner_data.common);
        outer_builder.register_public_inputs(&outer_proof_target.public_inputs);
        outer_builder.register_public_inputs(&outer_verifier_data.circuit_digest.elements);

        let outer_data = outer_builder.build::<PoseidonBN128GoldilocksConfig>();

        let mut outer_pw = PartialWitness::new();
        outer_pw.set_proof_with_pis_target(&outer_proof_target, &inner_proof);
        outer_pw.set_verifier_data_target(&outer_verifier_data, &inner_data.verifier_only);


        let mut timing = TimingTree::new("step proof gen", Level::Info);
        let outer_proof = prove::<F, PoseidonBN128GoldilocksConfig, D>(&outer_data.prover_only, &outer_data.common, outer_pw.clone(), &mut timing).unwrap();
        timing.print();

        let ret = outer_data.verify(outer_proof.clone());

        // Verify the public inputs:

        assert_eq!(outer_proof.public_inputs.len(), 36);

        // Blake2b hash of the public inputs
        assert_eq!(
            outer_proof.public_inputs[0..32].iter()
            .map(|element| u8::try_from(element.to_canonical_u64()).unwrap()).collect::<Vec<_>>(),
            hex::decode(BLOCK_530527_PUBLIC_INPUTS_HASH).unwrap(),
        );

        /*  TODO:  It appears that the circuit digest changes after every different run, even if none of the code changes.  Need to find out why.
        // Step circuit's digest
        assert_eq!(
            outer_proof.public_inputs[32..36].iter()
            .map(|element| element.to_canonical_u64()).collect::<Vec<_>>(),
            [17122441374070351185, 18368451173317844989, 5752543660850962321, 1428786498560175815],
        );
        */

        for gate in outer_data.common.gates.iter() {
            println!("outer circuit: gate is {:?}", gate);
        }

        println!("Recursive circuit digest is {:?}", outer_data.verifier_only.circuit_digest);

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

    #[test]
    fn test_operator_test_case() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        type Curve = Ed25519;

        let headers = vec![
            [54, 115, 158, 107, 120, 233, 121, 250, 121, 187, 210, 98, 170, 57, 7, 75, 254, 120, 126, 248, 152, 207, 92, 73, 73, 95, 107, 230, 34, 1, 57, 35, 50, 35, 6, 0, 126, 114, 94, 23, 162, 130, 71, 71, 55, 66, 114, 81, 125, 20, 205, 17, 7, 52, 135, 19, 162, 175, 199, 112, 140, 249, 118, 31, 100, 202, 167, 91, 119, 128, 174, 144, 94, 172, 52, 151, 95, 223, 33, 72, 198, 171, 75, 98, 243, 178, 43, 222, 20, 236, 74, 102, 239, 194, 72, 95, 100, 145, 178, 195, 8, 6, 66, 65, 66, 69, 181, 1, 1, 14, 0, 0, 0, 15, 231, 7, 5, 0, 0, 0, 0, 248, 48, 100, 145, 103, 101, 129, 207, 60, 241, 179, 192, 249, 87, 142, 105, 112, 173, 150, 20, 7, 149, 243, 108, 141, 166, 202, 151, 244, 71, 251, 74, 162, 199, 106, 196, 12, 28, 164, 194, 159, 93, 41, 141, 38, 116, 84, 75, 156, 117, 86, 64, 235, 174, 220, 149, 7, 19, 125, 144, 35, 178, 7, 11, 46, 116, 90, 201, 0, 247, 85, 206, 234, 38, 182, 130, 101, 172, 107, 253, 156, 202, 80, 179, 189, 188, 245, 59, 41, 89, 47, 141, 174, 228, 93, 4, 5, 66, 65, 66, 69, 1, 1, 30, 227, 237, 216, 7, 88, 218, 58, 181, 73, 196, 1, 86, 69, 169, 177, 214, 18, 216, 29, 166, 95, 218, 201, 255, 6, 138, 225, 141, 232, 237, 82, 5, 102, 185, 210, 161, 46, 124, 82, 240, 194, 155, 53, 64, 160, 7, 130, 82, 102, 197, 102, 228, 123, 77, 7, 113, 203, 75, 32, 94, 31, 198, 138, 0, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 178, 166, 249, 97, 24, 101, 172, 103, 142, 15, 180, 69, 34, 147, 248, 69, 140, 159, 133, 193, 131, 116, 215, 51, 244, 245, 158, 4, 165, 165, 212, 77, 67, 0, 133, 82, 83, 136, 118, 181, 145, 144, 14, 99, 164, 136, 217, 77, 178, 166, 249, 97, 24, 101, 172, 103, 142, 15, 180, 69, 34, 147, 248, 69, 140, 159, 133, 193, 131, 116, 215, 51, 244, 245, 158, 4, 165, 165, 212, 77, 67, 0, 133, 82, 83, 136, 118, 181, 145, 144, 14, 99, 164, 136, 217, 77, 4, 0].to_vec(),
            [110, 200, 76, 124, 73, 75, 0, 3, 21, 170, 7, 121, 42, 201, 131, 173, 74, 209, 53, 202, 155, 147, 36, 135, 194, 245, 139, 117, 216, 8, 184, 170, 54, 35, 6, 0, 242, 100, 119, 170, 241, 248, 151, 221, 7, 153, 28, 136, 150, 48, 162, 87, 119, 175, 247, 21, 63, 141, 167, 203, 28, 32, 49, 67, 239, 69, 50, 131, 228, 15, 164, 250, 18, 142, 58, 111, 7, 206, 36, 34, 186, 239, 200, 226, 81, 227, 86, 29, 230, 7, 25, 139, 196, 67, 196, 47, 124, 195, 193, 151, 8, 6, 66, 65, 66, 69, 181, 1, 3, 24, 0, 0, 0, 16, 231, 7, 5, 0, 0, 0, 0, 178, 165, 214, 196, 187, 214, 111, 173, 60, 58, 153, 9, 152, 52, 134, 25, 23, 170, 82, 63, 133, 206, 62, 10, 143, 156, 2, 235, 38, 137, 214, 21, 167, 194, 213, 230, 164, 169, 230, 19, 202, 27, 40, 35, 158, 106, 159, 153, 132, 168, 66, 144, 143, 194, 15, 93, 60, 132, 120, 201, 118, 61, 77, 4, 242, 66, 21, 182, 0, 200, 94, 229, 222, 176, 94, 78, 99, 66, 219, 105, 201, 193, 108, 205, 193, 31, 47, 200, 230, 197, 161, 183, 26, 118, 192, 9, 5, 66, 65, 66, 69, 1, 1, 154, 102, 25, 238, 207, 222, 189, 214, 129, 247, 156, 74, 25, 150, 34, 245, 23, 99, 41, 145, 30, 144, 103, 222, 87, 38, 178, 131, 179, 197, 150, 122, 198, 207, 250, 157, 132, 137, 69, 198, 125, 16, 150, 159, 8, 253, 236, 57, 55, 152, 196, 10, 90, 226, 96, 107, 92, 113, 76, 229, 90, 167, 132, 132, 0, 4, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 138, 225, 151, 6, 149, 144, 14, 225, 224, 149, 3, 230, 15, 95, 234, 200, 167, 201, 2, 196, 131, 252, 77, 70, 88, 40, 79, 230, 210, 77, 43, 110, 111, 144, 224, 54, 217, 106, 157, 240, 127, 160, 255, 61, 244, 82, 218, 124, 138, 225, 151, 6, 149, 144, 14, 225, 224, 149, 3, 230, 15, 95, 234, 200, 167, 201, 2, 196, 131, 252, 77, 70, 88, 40, 79, 230, 210, 77, 43, 110, 111, 144, 224, 54, 217, 106, 157, 240, 127, 160, 255, 61, 244, 82, 218, 124, 60, 0].to_vec(),
            [64, 195, 182, 92, 199, 22, 38, 83, 132, 193, 225, 54, 249, 233, 118, 114, 20, 57, 227, 75, 162, 44, 131, 53, 55, 25, 193, 236, 56, 187, 248, 134, 58, 35, 6, 0, 140, 24, 33, 178, 125, 199, 11, 17, 181, 53, 39, 18, 196, 229, 36, 200, 247, 10, 159, 13, 144, 64, 5, 33, 246, 39, 87, 196, 81, 182, 193, 87, 29, 70, 240, 96, 3, 74, 88, 158, 0, 42, 64, 114, 114, 136, 213, 208, 97, 140, 149, 129, 234, 29, 136, 230, 85, 194, 32, 81, 116, 197, 249, 107, 8, 6, 66, 65, 66, 69, 181, 1, 3, 20, 0, 0, 0, 17, 231, 7, 5, 0, 0, 0, 0, 34, 166, 91, 72, 132, 113, 179, 227, 37, 100, 85, 249, 17, 198, 103, 49, 71, 184, 239, 177, 58, 172, 79, 80, 63, 33, 248, 26, 194, 195, 242, 32, 82, 146, 137, 112, 206, 117, 50, 87, 80, 70, 115, 103, 24, 50, 213, 132, 0, 187, 89, 213, 58, 94, 160, 132, 113, 205, 145, 230, 109, 181, 109, 14, 57, 213, 146, 49, 162, 163, 206, 135, 111, 229, 111, 158, 255, 126, 109, 4, 141, 97, 103, 177, 27, 177, 180, 81, 29, 58, 208, 255, 93, 147, 103, 0, 5, 66, 65, 66, 69, 1, 1, 250, 62, 103, 95, 103, 141, 95, 145, 112, 25, 195, 178, 227, 102, 69, 90, 27, 195, 235, 109, 120, 72, 157, 74, 173, 139, 50, 188, 46, 108, 186, 109, 12, 21, 237, 175, 100, 214, 245, 174, 41, 88, 249, 4, 139, 171, 19, 67, 53, 193, 114, 71, 110, 249, 161, 15, 164, 197, 120, 38, 178, 161, 90, 133, 0, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 172, 93, 159, 1, 56, 68, 128, 86, 81, 229, 145, 138, 109, 28, 159, 28, 253, 168, 166, 59, 53, 55, 98, 17, 141, 135, 133, 24, 137, 143, 47, 77, 168, 241, 24, 92, 147, 92, 158, 13, 189, 249, 63, 31, 223, 250, 160, 216, 172, 93, 159, 1, 56, 68, 128, 86, 81, 229, 145, 138, 109, 28, 159, 28, 253, 168, 166, 59, 53, 55, 98, 17, 141, 135, 133, 24, 137, 143, 47, 77, 168, 241, 24, 92, 147, 92, 158, 13, 189, 249, 63, 31, 223, 250, 160, 216, 4, 0].to_vec(),
            [112, 124, 39, 106, 46, 165, 89, 190, 159, 103, 121, 212, 218, 235, 206, 55, 174, 151, 242, 70, 197, 163, 141, 125, 167, 75, 29, 20, 132, 243, 125, 78, 62, 35, 6, 0, 131, 88, 247, 204, 159, 253, 88, 233, 31, 61, 158, 5, 10, 86, 74, 65, 254, 126, 82, 133, 127, 9, 235, 49, 117, 120, 171, 34, 102, 142, 67, 32, 33, 133, 135, 98, 138, 23, 117, 93, 225, 61, 117, 219, 177, 188, 186, 204, 241, 104, 169, 178, 130, 31, 38, 157, 84, 111, 134, 156, 99, 97, 39, 53, 8, 6, 66, 65, 66, 69, 181, 1, 1, 1, 0, 0, 0, 18, 231, 7, 5, 0, 0, 0, 0, 160, 110, 123, 247, 36, 44, 91, 201, 205, 136, 181, 24, 209, 219, 151, 192, 29, 207, 229, 169, 141, 98, 144, 244, 143, 54, 241, 9, 30, 141, 64, 32, 27, 119, 120, 139, 226, 239, 49, 193, 229, 238, 199, 230, 18, 160, 145, 63, 2, 209, 2, 106, 113, 213, 181, 139, 178, 181, 210, 49, 89, 46, 50, 2, 175, 226, 176, 95, 110, 34, 193, 43, 135, 160, 245, 174, 22, 63, 151, 32, 181, 205, 82, 68, 170, 214, 213, 37, 173, 216, 79, 221, 48, 41, 208, 3, 5, 66, 65, 66, 69, 1, 1, 138, 20, 34, 40, 189, 192, 135, 182, 33, 71, 111, 226, 97, 234, 125, 202, 173, 200, 145, 82, 126, 163, 15, 136, 44, 241, 116, 213, 28, 241, 10, 125, 141, 165, 171, 202, 8, 133, 20, 141, 187, 250, 187, 55, 163, 195, 233, 130, 146, 166, 60, 112, 232, 160, 59, 149, 143, 150, 173, 131, 106, 17, 176, 130, 0, 4, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 134, 32, 164, 5, 75, 219, 72, 205, 157, 212, 13, 180, 60, 179, 9, 162, 117, 90, 208, 121, 180, 211, 179, 199, 37, 11, 38, 50, 32, 146, 77, 164, 84, 44, 40, 49, 132, 128, 181, 50, 171, 255, 219, 222, 88, 154, 198, 46, 134, 32, 164, 5, 75, 219, 72, 205, 157, 212, 13, 180, 60, 179, 9, 162, 117, 90, 208, 121, 180, 211, 179, 199, 37, 11, 38, 50, 32, 146, 77, 164, 84, 44, 40, 49, 132, 128, 181, 50, 171, 255, 219, 222, 88, 154, 198, 46, 4, 0].to_vec(),
            [167, 234, 10, 89, 188, 85, 75, 118, 29, 8, 78, 168, 217, 39, 212, 213, 225, 154, 124, 81, 31, 192, 42, 102, 206, 139, 77, 0, 115, 152, 129, 225, 66, 35, 6, 0, 178, 77, 240, 37, 173, 94, 159, 149, 164, 248, 179, 185, 203, 221, 73, 131, 154, 216, 238, 33, 232, 155, 53, 41, 247, 172, 230, 190, 1, 151, 192, 110, 110, 248, 213, 1, 97, 196, 222, 147, 6, 140, 47, 232, 216, 80, 110, 88, 243, 135, 187, 16, 147, 229, 47, 36, 139, 47, 80, 255, 101, 144, 70, 53, 8, 6, 66, 65, 66, 69, 181, 1, 3, 26, 0, 0, 0, 19, 231, 7, 5, 0, 0, 0, 0, 250, 51, 3, 12, 136, 121, 100, 77, 103, 74, 51, 15, 10, 24, 77, 55, 152, 4, 59, 227, 246, 155, 107, 186, 50, 79, 72, 134, 47, 14, 199, 66, 103, 12, 255, 225, 138, 108, 175, 246, 176, 241, 187, 38, 47, 27, 235, 78, 158, 215, 113, 141, 179, 8, 196, 163, 119, 78, 102, 233, 32, 46, 110, 13, 138, 243, 56, 63, 75, 8, 247, 92, 200, 39, 113, 34, 155, 1, 106, 143, 153, 18, 95, 241, 162, 65, 200, 6, 27, 31, 102, 94, 66, 172, 216, 4, 5, 66, 65, 66, 69, 1, 1, 226, 60, 5, 243, 97, 252, 63, 163, 203, 198, 91, 169, 221, 77, 125, 17, 212, 140, 122, 28, 246, 102, 181, 107, 159, 176, 219, 232, 249, 207, 120, 114, 59, 73, 121, 218, 199, 121, 67, 74, 215, 54, 31, 203, 86, 20, 10, 157, 158, 204, 126, 136, 209, 27, 254, 175, 10, 117, 60, 191, 23, 84, 182, 135, 0, 4, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 129, 1, 149, 144, 69, 78, 245, 222, 126, 35, 80, 67, 248, 81, 44, 175, 104, 26, 174, 5, 242, 143, 213, 95, 10, 118, 7, 124, 234, 215, 137, 167, 208, 101, 212, 73, 15, 159, 106, 210, 176, 195, 45, 42, 202, 73, 232, 141, 4, 246, 149, 144, 69, 78, 245, 222, 126, 35, 80, 67, 248, 81, 44, 175, 104, 26, 174, 5, 242, 143, 213, 95, 10, 118, 7, 124, 234, 215, 137, 167, 208, 101, 212, 73, 15, 159, 106, 210, 176, 195, 45, 42, 202, 73, 232, 141, 4, 246, 60, 0].to_vec(),
        ];

        let head_block_hash = hex::decode("36739e6b78e979fa79bbd262aa39074bfe787ef898cf5c49495f6be622013923").unwrap();
        let head_block_num = 100555;

        let public_inputs_hash = hex::decode("d28e3a69ea8b7a4994f1fc1db914cc2d91e84275fd5c0f573dd2756d5c6df18b").unwrap();

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

        pw.set_avail_hash_target(&step_target.public_inputs_hash, &(public_inputs_hash.try_into().unwrap()));

        set_precommits_pw::<F, D, Curve>(
            &mut pw,
            step_target.precommits.to_vec(),
            (0..QUORUM_SIZE).map(|_| [1, 221, 226, 250, 11, 92, 6, 148, 162, 108, 157, 22, 56, 188, 154, 11, 226, 175, 133, 94, 113, 173, 18, 197, 114, 50, 88, 224, 126, 221, 137, 28, 193, 208, 136, 1, 0, 132, 31, 0, 0, 0, 0, 0, 0, 94, 0, 0, 0, 0, 0, 0, 0].clone().to_vec()).collect::<Vec<_>>(),
            [
	            [70, 38, 147, 208, 74, 111, 204, 157, 52, 110, 52, 184, 219, 139, 117, 103, 83, 100, 16, 134, 3, 252, 72, 48, 221, 218, 234, 52, 188, 130, 192, 94, 92, 22, 2, 92, 253, 140, 20, 106, 159, 11, 200, 25, 71, 220, 203, 17, 113, 137, 137, 11, 116, 143, 194, 188, 165, 46, 101, 211, 98, 189, 203, 0].to_vec(), 
            	[243, 98, 147, 25, 128, 119, 5, 148, 122, 111, 111, 245, 178, 229, 115, 24, 28, 131, 217, 187, 67, 90, 207, 211, 148, 140, 243, 67, 69, 129, 196, 109, 6, 69, 191, 144, 27, 206, 155, 152, 12, 249, 90, 56, 160, 83, 216, 225, 240, 244, 154, 212, 76, 130, 52, 195, 178, 180, 32, 37, 245, 0, 76, 10].to_vec(), 
            	[122, 111, 105, 248, 151, 187, 156, 252, 232, 101, 89, 175, 177, 18, 193, 246, 215, 194, 110, 20, 85, 246, 68, 137, 52, 139, 54, 111, 88, 86, 106, 6, 8, 91, 0, 252, 122, 107, 179, 137, 236, 178, 130, 178, 96, 169, 152, 241, 86, 112, 18, 110, 156, 173, 162, 148, 5, 252, 127, 163, 27, 242, 153, 4].to_vec(), 
            	[30, 16, 14, 215, 12, 125, 145, 139, 125, 185, 236, 161, 82, 34, 58, 184, 121, 159, 193, 143, 20, 49, 95, 235, 22, 213, 222, 110, 104, 90, 4, 104, 213, 18, 145, 113, 128, 101, 4, 180, 239, 248, 237, 133, 65, 156, 46, 6, 35, 103, 162, 240, 118, 232, 87, 161, 84, 192, 61, 138, 216, 44, 242, 2].to_vec(), 
            	[39, 204, 143, 237, 235, 223, 138, 72, 181, 123, 132, 35, 109, 244, 101, 177, 53, 209, 123, 122, 233, 162, 62, 191, 23, 59, 111, 247, 156, 47, 46, 41, 66, 59, 222, 196, 160, 190, 21, 96, 64, 164, 253, 37, 169, 139, 170, 140, 157, 146, 156, 50, 55, 215, 88, 124, 159, 93, 60, 207, 232, 187, 136, 7].to_vec(),
            	[82, 18, 15, 8, 65, 150, 177, 119, 128, 172, 199, 104, 194, 169, 218, 156, 169, 118, 32, 1, 217, 133, 165, 200, 246, 131, 33, 236, 91, 154, 230, 54, 137, 148, 193, 3, 15, 240, 166, 202, 17, 60, 51, 77, 55, 152, 85, 188, 183, 197, 11, 246, 108, 141, 29, 104, 126, 211, 140, 171, 102, 60, 138, 10].to_vec(), 
            	[32, 2, 137, 240, 79, 62, 0, 67, 0, 67, 130, 11, 32, 48, 9, 190, 198, 255, 139, 180, 134, 198, 137, 193, 156, 71, 205, 101, 101, 83, 110, 5, 168, 84, 174, 116, 74, 195, 145, 153, 165, 251, 153, 182, 95, 7, 12, 226, 127, 202, 247, 119, 174, 124, 78, 189, 136, 116, 134, 129, 227, 47, 217, 10].to_vec(),
            ].to_vec(),
            [0, 1, 2, 3, 4, 5, 6].to_vec(),
            [
            	[2, 248, 6, 149, 240, 164, 162, 48, 130, 70, 200, 129, 52, 178, 222, 117, 158, 52, 125, 82, 113, 137, 116, 45, 212, 46, 152, 114, 75, 213, 169, 188].to_vec(),
            	[9, 32, 5, 166, 247, 165, 138, 152, 223, 95, 155, 141, 24, 107, 152, 119, 241, 43, 96, 58, 160, 108, 125, 235, 240, 246, 16, 213, 164, 159, 158, 215].to_vec(),
            	[10, 151, 143, 214, 89, 198, 148, 72, 39, 62, 53, 85, 78, 33, 186, 195, 84, 88, 254, 43, 25, 159, 139, 143, 184, 26, 100, 136, 238, 153, 199, 52].to_vec(), 
            	[38, 43, 94, 9, 91, 48, 154, 242, 176, 234, 225, 197, 84, 224, 59, 108, 196, 165, 160, 223, 32, 123, 102, 43, 50, 150, 35, 242, 127, 220, 232, 208].to_vec(),
            	[41, 16, 221, 236, 124, 81, 178, 234, 180, 217, 104, 49, 168, 185, 232, 74, 66, 206, 189, 173, 174, 98, 189, 234, 38, 202, 123, 12, 100, 14, 138, 33].to_vec(),
            	[55, 188, 151, 23, 201, 155, 231, 101, 245, 89, 141, 25, 147, 251, 91, 194, 253, 95, 182, 140, 189, 129, 121, 91, 92, 3, 71, 47, 13, 192, 36, 161].to_vec(),
            	[68, 132, 228, 52, 110, 176, 184, 148, 241, 72, 35, 77, 217, 236, 115, 106, 45, 55, 196, 40, 174, 25, 27, 131, 89, 237, 155, 3, 176, 246, 1, 125].to_vec(),
            	[248, 108, 114, 39, 126, 210, 14, 254, 21, 186, 177, 171, 207, 52, 101, 110, 125, 35, 54, 228, 33, 51, 250, 153, 51, 30, 135, 75, 84, 88, 178, 143].to_vec(),
            	[152, 68, 130, 180, 141, 53, 108, 232, 226, 153, 38, 139, 16, 12, 97, 169, 186, 95, 150, 167, 87, 207, 152, 21, 6, 131, 163, 232, 170, 133, 72, 74].to_vec(),
            	[77, 48, 168, 172, 184, 141, 43, 194, 177, 174, 70, 165, 231, 96, 206, 66, 51, 192, 187, 156, 3, 165, 116, 34, 0, 157, 108, 44, 208, 179, 54, 122].to_vec(),
            	[151, 138, 6, 255, 23, 149, 106, 253, 92, 187, 138, 30, 133, 38, 125, 204, 173, 158, 160, 174, 245, 203, 117, 241, 194, 42, 241, 186, 242, 144, 19, 88].to_vec(),
            	[119, 45, 110, 19, 161, 81, 154, 67, 175, 204, 158, 121, 180, 85, 108, 151, 46, 144, 179, 128, 242, 137, 217, 147, 80, 98, 83, 201, 222, 30, 221, 28].to_vec(),
            	[110, 89, 180, 40, 128, 169, 153, 44, 210, 177, 176, 139, 125, 162, 100, 48, 161, 133, 125, 141, 8, 136, 227, 35, 236, 99, 51, 157, 187, 172, 207, 71].to_vec(),
            	[217, 33, 79, 221, 50, 93, 137, 43, 35, 211, 117, 243, 102, 71, 141, 247, 242, 164, 38, 249, 242, 155, 102, 194, 201, 250, 81, 121, 84, 194, 242, 195].to_vec(),
            	[145, 198, 46, 104, 102, 216, 182, 140, 27, 14, 83, 223, 13, 15, 15, 79, 24, 114, 120, 219, 48, 199, 185, 93, 39, 65, 244, 208, 200, 197, 149, 7].to_vec(),
            	[100, 130, 224, 145, 23, 222, 96, 138, 109, 208, 202, 214, 88, 59, 192, 68, 32, 12, 121, 48, 132, 72, 227, 42, 43, 195, 169, 127, 221, 176, 188, 72].to_vec(),
            ].to_vec(),
        );

        set_authority_set_pw::<F, D, Curve>(
            &mut pw,
            &step_target.authority_set,
            [
            	[2, 248, 6, 149, 240, 164, 162, 48, 130, 70, 200, 129, 52, 178, 222, 117, 158, 52, 125, 82, 113, 137, 116, 45, 212, 46, 152, 114, 75, 213, 169, 188].to_vec(),
            	[9, 32, 5, 166, 247, 165, 138, 152, 223, 95, 155, 141, 24, 107, 152, 119, 241, 43, 96, 58, 160, 108, 125, 235, 240, 246, 16, 213, 164, 159, 158, 215].to_vec(),
            	[10, 151, 143, 214, 89, 198, 148, 72, 39, 62, 53, 85, 78, 33, 186, 195, 84, 88, 254, 43, 25, 159, 139, 143, 184, 26, 100, 136, 238, 153, 199, 52].to_vec(), 
            	[38, 43, 94, 9, 91, 48, 154, 242, 176, 234, 225, 197, 84, 224, 59, 108, 196, 165, 160, 223, 32, 123, 102, 43, 50, 150, 35, 242, 127, 220, 232, 208].to_vec(),
            	[41, 16, 221, 236, 124, 81, 178, 234, 180, 217, 104, 49, 168, 185, 232, 74, 66, 206, 189, 173, 174, 98, 189, 234, 38, 202, 123, 12, 100, 14, 138, 33].to_vec(),
            	[55, 188, 151, 23, 201, 155, 231, 101, 245, 89, 141, 25, 147, 251, 91, 194, 253, 95, 182, 140, 189, 129, 121, 91, 92, 3, 71, 47, 13, 192, 36, 161].to_vec(),
            	[68, 132, 228, 52, 110, 176, 184, 148, 241, 72, 35, 77, 217, 236, 115, 106, 45, 55, 196, 40, 174, 25, 27, 131, 89, 237, 155, 3, 176, 246, 1, 125].to_vec(),
            	[248, 108, 114, 39, 126, 210, 14, 254, 21, 186, 177, 171, 207, 52, 101, 110, 125, 35, 54, 228, 33, 51, 250, 153, 51, 30, 135, 75, 84, 88, 178, 143].to_vec(),
            	[152, 68, 130, 180, 141, 53, 108, 232, 226, 153, 38, 139, 16, 12, 97, 169, 186, 95, 150, 167, 87, 207, 152, 21, 6, 131, 163, 232, 170, 133, 72, 74].to_vec(),
            	[77, 48, 168, 172, 184, 141, 43, 194, 177, 174, 70, 165, 231, 96, 206, 66, 51, 192, 187, 156, 3, 165, 116, 34, 0, 157, 108, 44, 208, 179, 54, 122].to_vec(),
            	[151, 138, 6, 255, 23, 149, 106, 253, 92, 187, 138, 30, 133, 38, 125, 204, 173, 158, 160, 174, 245, 203, 117, 241, 194, 42, 241, 186, 242, 144, 19, 88].to_vec(),
            	[119, 45, 110, 19, 161, 81, 154, 67, 175, 204, 158, 121, 180, 85, 108, 151, 46, 144, 179, 128, 242, 137, 217, 147, 80, 98, 83, 201, 222, 30, 221, 28].to_vec(),
            	[110, 89, 180, 40, 128, 169, 153, 44, 210, 177, 176, 139, 125, 162, 100, 48, 161, 133, 125, 141, 8, 136, 227, 35, 236, 99, 51, 157, 187, 172, 207, 71].to_vec(),
            	[217, 33, 79, 221, 50, 93, 137, 43, 35, 211, 117, 243, 102, 71, 141, 247, 242, 164, 38, 249, 242, 155, 102, 194, 201, 250, 81, 121, 84, 194, 242, 195].to_vec(),
            	[145, 198, 46, 104, 102, 216, 182, 140, 27, 14, 83, 223, 13, 15, 15, 79, 24, 114, 120, 219, 48, 199, 185, 93, 39, 65, 244, 208, 200, 197, 149, 7].to_vec(),
            	[100, 130, 224, 145, 23, 222, 96, 138, 109, 208, 202, 214, 88, 59, 192, 68, 32, 12, 121, 48, 132, 72, 227, 42, 43, 195, 169, 127, 221, 176, 188, 72].to_vec(),
            ].to_vec(),
            94,
            hex::decode("8e6866fa26ff254cdb0c2d7adf78b551a108770400317886aeb22f90556edeb9").unwrap(),
        );

        let inner_data = builder.build();
        let inner_proof = gen_step_proof::<F, C, D>(&inner_data, &pw);
        inner_data.verify(inner_proof.clone()).unwrap();

        println!("inner circuit digest is {:?}", inner_data.verifier_only.circuit_digest);

        let mut outer_builder = CircuitBuilder::<F, D>::new(CircuitConfig::standard_recursion_config());
        let outer_proof_target = outer_builder.add_virtual_proof_with_pis(&inner_data.common);
        let outer_verifier_data = outer_builder.add_virtual_verifier_data(inner_data.common.config.fri_config.cap_height);
        outer_builder.verify_proof::<C>(&outer_proof_target, &outer_verifier_data, &inner_data.common);
        outer_builder.register_public_inputs(&outer_proof_target.public_inputs);
        outer_builder.register_public_inputs(&outer_verifier_data.circuit_digest.elements);

        let outer_data = outer_builder.build::<PoseidonBN128GoldilocksConfig>();

        let mut outer_pw = PartialWitness::new();
        outer_pw.set_proof_with_pis_target(&outer_proof_target, &inner_proof);
        outer_pw.set_verifier_data_target(&outer_verifier_data, &inner_data.verifier_only);


        let mut timing = TimingTree::new("step proof gen", Level::Info);
        let outer_proof = prove::<F, PoseidonBN128GoldilocksConfig, D>(&outer_data.prover_only, &outer_data.common, outer_pw.clone(), &mut timing).unwrap();
        timing.print();

        let ret = outer_data.verify(outer_proof.clone());

        // Verify the public inputs:

        assert_eq!(outer_proof.public_inputs.len(), 36);

        // Blake2b hash of the public inputs
        assert_eq!(
            outer_proof.public_inputs[0..32].iter()
            .map(|element| u8::try_from(element.to_canonical_u64()).unwrap()).collect::<Vec<_>>(),
            hex::decode("d28e3a69ea8b7a4994f1fc1db914cc2d91e84275fd5c0f573dd2756d5c6df18b").unwrap(),
        );

        /*  TODO:  It appears that the circuit digest changes after every different run, even if none of the code changes.  Need to find out why.
        // Step circuit's digest
        assert_eq!(
            outer_proof.public_inputs[32..36].iter()
            .map(|element| element.to_canonical_u64()).collect::<Vec<_>>(),
            [17122441374070351185, 18368451173317844989, 5752543660850962321, 1428786498560175815],
        );
        */

        for gate in outer_data.common.gates.iter() {
            println!("outer circuit: gate is {:?}", gate);
        }

        println!("Recursive circuit digest is {:?}", outer_data.verifier_only.circuit_digest);

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