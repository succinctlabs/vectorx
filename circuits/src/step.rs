use plonky2lib_succinct::{ed25519::curve::curve_types::Curve, hash_functions::blake2b::CHUNK_128_BYTES};
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

pub trait CircuitBuilderIVC {
    fn process_header(
        &mut self,
        encoded_header: &EncodedHeaderTarget,
        encoded_header_size: Target,
        parent_block_num: Target,
        parent_hash: &AvailHashTarget,
        pih_acc: &AvailHashTarget,
    );
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderIVC for CircuitBuilder<F, D> {
    fn process_header(
        &mut self,
        encoded_header: &EncodedHeaderTarget,
        encoded_header_size: Target,
        parent_block_num: Target,
        parent_hash_target: &AvailHashTarget,
        pih_acc_target: &AvailHashTarget,
    ) {
        // Get the decoded_header object to retrieve the block numbers and parent hashes
        let decoded_header = self.decode_header(encoded_header);

        // Verify that this header's block number is one greater than the previous header's block number
        let one = self.one();
        let expected_block_num = self.add(parent_block_num, one);
        self.connect(expected_block_num, decoded_header.block_number);
        self.register_public_input(decoded_header.block_number);

        // Verify that the parent hash is equal to the decoded parent hash
        self.connect_hash(parent_hash_target.clone(), decoded_header.parent_hash);

        // Calculate the hash for the current header
        let header_hasher = make_blake2b_circuit(
            self,
            MAX_HEADER_SIZE * 8,
            HASH_SIZE
        );

        // Input the encoded header bytes into the hasher
        for i in 0..MAX_HEADER_SIZE {
            // Need to split the bytes into bits
            let mut bits = self.split_le(encoded_header.header_bytes[i], 8);

            // Needs to be in bit big endian order for the EDDSA verification circuit
            bits.reverse();
            for (j, bit) in bits.iter().enumerate().take(8){
                self.connect(header_hasher.message[i*8+j].target, bit.target);
            }
        }

        self.connect(header_hasher.message_len, encoded_header_size);

        // Calculate the hash of the extracted fields and add them into the accumulator
        let pih_acc_hasher = make_blake2b_circuit(
            self,
            CHUNK_128_BYTES * 8,
            HASH_SIZE,
        );

        let mut hasher_idx = 0;
        // Input the accumulator
        for hash_byte in pih_acc_target.0.iter() {
            let mut bits = self.split_le(*hash_byte, 8);

            bits.reverse();
            assert!(bits.len() == 8);
            for bit in bits.iter() {
                self.connect(pih_acc_hasher.message[hasher_idx].target, bit.target);
                hasher_idx += 1;
            }
        }

        // Input the header hash
        for bit in header_hasher.digest.iter() {
            self.connect(pih_acc_hasher.message[hasher_idx].target, bit.target);
            hasher_idx += 1;
        }

        // Input the state root
        for byte in decoded_header.state_root.0.iter() {
            let mut bits = self.split_le(*byte, 8);

            bits.reverse();
            assert!(bits.len() == 8);
            for bit in bits.iter() {
                self.connect(pih_acc_hasher.message[hasher_idx].target, bit.target);
                hasher_idx += 1;
            }
        }

        for i in hasher_idx..CHUNK_128_BYTES * 8 {
            let zero = self.zero();
            self.connect(pih_acc_hasher.message[i].target, zero);
        }

        let input_len = self.constant(F::from_canonical_usize((hasher_idx+1)/8));
        self.connect(pih_acc_hasher.message_len, input_len);

        for byte_chunk in header_hasher.digest.chunks(8) {
            let byte = self.le_sum(byte_chunk.to_vec().iter().rev());
            self.register_public_input(byte);
        }

        for byte_chunk in pih_acc_hasher.digest.chunks(8) {
            let byte = self.le_sum(byte_chunk.to_vec().iter().rev());
            self.register_public_input(byte);
        }

    }
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
            1408 * 8,
            HASH_SIZE,
        );

        for (i, bit) in public_inputs_hash_input.iter().enumerate() {
            self.connect(bit.target, public_inputs_hash_circuit.message[i].target);
        }

        // Add the padding
        let zero = self.zero();
        for i in public_inputs_hash_input.len() .. 1408 * 8 {
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

    use anyhow::{Result, Ok};
    use log::Level;
    use plonky2::fri::{FriConfig, FriParams};
    use plonky2::fri::reduction_strategies::FriReductionStrategy;
    use plonky2::gates::arithmetic_base::ArithmeticGate;
    use plonky2::gates::arithmetic_extension::ArithmeticExtensionGate;
    use plonky2::gates::base_sum::BaseSumGate;
    use plonky2::gates::constant::ConstantGate;
    use plonky2::gates::coset_interpolation::CosetInterpolationGate;
    use plonky2::gates::exponentiation::ExponentiationGate;
    use plonky2::gates::gate::GateRef;
    use plonky2::gates::multiplication_extension::MulExtensionGate;
    use plonky2::gates::noop::NoopGate;
    use plonky2::gates::poseidon::PoseidonGate;
    use plonky2::gates::poseidon_mds::PoseidonMdsGate;
    use plonky2::gates::public_input::PublicInputGate;
    use plonky2::gates::random_access::RandomAccessGate;
    use plonky2::gates::reducing::ReducingGate;
    use plonky2::gates::reducing_extension::ReducingExtensionGate;
    use plonky2::gates::selectors::SelectorsInfo;
    use plonky2::hash::hash_types::RichField;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::{CircuitConfig, CircuitData, CommonCircuitData};
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2::plonk::proof::ProofWithPublicInputs;
    use plonky2::plonk::prover::prove;
    use plonky2::recursion::cyclic_recursion::check_cyclic_proof_verifier_data;
    use plonky2::recursion::dummy_circuit::cyclic_base_proof;
    use plonky2::util::timing::TimingTree;
    use plonky2_field::extension::Extendable;
    use plonky2_field::types::{Field, PrimeField64};
    use plonky2_u32::gates::add_many_u32::U32AddManyGate;
    use plonky2lib_succinct::ed25519::curve::ed25519::Ed25519;

    use crate::justification::{set_precommits_pw, set_authority_set_pw};
    use crate::plonky2_config::PoseidonBN128GoldilocksConfig;
    use crate::step::{make_step_circuit, CircuitBuilderIVC};
    use crate::utils::{QUORUM_SIZE, WitnessAvailHash, WitnessEncodedHeader, CircuitBuilderUtils, AvailHashTarget};
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
    fn test_process_header_ivc() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let head_block_num = builder.add_virtual_public_input();
        let head_block_hash = builder.add_virtual_avail_hash_target_safe(true);
        let initial_accumulator = builder.add_virtual_avail_hash_target_safe(true);

        let current_block_num = builder.add_virtual_target();
        let current_block_hash = builder.add_virtual_avail_hash_target_safe(false);
        let current_accumulator = builder.add_virtual_avail_hash_target_safe(false);

        let encoded_block_input = builder.add_virtual_encoded_header_target_safe();
        let encoded_block_size = builder.add_virtual_target();

        builder.process_header(
            &encoded_block_input,
            encoded_block_size,
            current_block_num,
            &current_block_hash,
            &current_accumulator,
        );

        let verifier_data_target = builder.add_verifier_data_public_inputs();

        let k_is = vec![1, 7, 49, 343, 2401, 16807, 117649, 823543, 5764801, 40353607, 282475249, 1977326743, 13841287201, 96889010407, 678223072849, 4747561509943, 33232930569601, 232630513987207, 1628413597910449, 11398895185373143, 79792266297612001, 558545864083284007, 3909821048582988049, 8922003270666332022, 7113790686420571191, 12903046666114829695, 16534350385145470581, 5059988279530788141, 16973173887300932666, 8131752794619022736, 1582037354089406189, 11074261478625843323, 3732854072722565977, 7683234439643377518, 16889152938674473984, 7543606154233811962, 15911754940807515092, 701820169165099718, 4912741184155698026, 15942444219675301861, 916645121239607101, 6416515848677249707, 8022122801911579307, 814627405137302186, 5702391835961115302, 3023254712898638472, 2716038920875884983, 565528376716610560, 3958698637016273920, 9264146389699333119, 9508792519651578870, 11221315429317299127, 4762231727562756605, 14888878023524711914, 11988425817600061793, 10132004445542095267, 15583798910550913906, 16852872026783475737, 7289639770996824233, 14133990258148600989, 6704211459967285318, 10035992080941828584, 14911712358349047125, 12148266161370408270, 11250886851934520606, 4969231685883306958, 16337877731768564385, 3684679705892444769, 7346013871832529062, 14528608963998534792, 9466542400916821939, 10925564598174000610, 2691975909559666986, 397087297503084581, 2779611082521592067, 1010533508236560148, 7073734557655921036, 12622653764762278610, 14571600075677612986, 9767480182670369297];
        let k_i_fields = k_is.iter().map(|x| plonky2_field::goldilocks_field::GoldilocksField(*x)).collect::<Vec<_>>();

        let barycentric_weights = vec![17293822565076172801,18374686475376656385,18446744069413535745,281474976645120,17592186044416,18446744069414584577,18446744000695107601,18446744065119617025,1152921504338411520,72057594037927936,18446744069415632897,18446462594437939201,18446726477228539905,18446744069414584065,68719476720,4294967296];
        let barycentric_weights_fields = barycentric_weights.iter().map(|x| plonky2_field::goldilocks_field::GoldilocksField(*x)).collect::<Vec<_>>();

        let common_data = CommonCircuitData::<F, D> {
            config: CircuitConfig {
                num_wires: 135,
                num_routed_wires: 80,
                num_constants: 2,
                use_base_arithmetic_gate: true,
                security_bits: 100,
                num_challenges: 2,
                zero_knowledge: false,
                max_quotient_degree_factor: 8,
                fri_config: FriConfig {
                    rate_bits: 3,
                    cap_height: 4,
                    proof_of_work_bits: 16,
                    reduction_strategy: FriReductionStrategy::ConstantArityBits(4, 5),
                    num_query_rounds: 28
                } 
            },
            fri_params: FriParams {
                config: FriConfig {
                    rate_bits: 3,
                    cap_height: 4,
                    proof_of_work_bits: 16,
                    reduction_strategy: FriReductionStrategy::ConstantArityBits(4, 5),
                    num_query_rounds: 28
                },
                hiding: false,
                degree_bits: 18,
                reduction_arity_bits: vec![4, 4, 4, 4],
            },
            gates: vec![
                GateRef::new(NoopGate{}),
                GateRef::new(ConstantGate{ num_consts: 2 }),
                GateRef::new(PoseidonMdsGate::new()),
                GateRef::new(PublicInputGate{}),
                GateRef::new(BaseSumGate::<2>::new(32)),
                GateRef::new(BaseSumGate::<2>::new(63)),
                GateRef::new(ReducingExtensionGate::new(32)),
                GateRef::new(ReducingGate::new(43)),
                GateRef::new(ArithmeticExtensionGate{num_ops: 10}),
                GateRef::new(ArithmeticGate{num_ops: 20}),
                GateRef::new(MulExtensionGate{num_ops: 13}),
                GateRef::new(RandomAccessGate{bits:2,num_copies:13,num_extra_constants:2, _phantom: std::marker::PhantomData }),
                GateRef::new(ExponentiationGate{num_power_bits: 66, _phantom: std::marker::PhantomData }),
                GateRef::new(U32AddManyGate{num_addends: 3, num_ops: 5, _phantom: std::marker::PhantomData }),
                GateRef::new(RandomAccessGate{bits: 4, num_copies: 4, num_extra_constants: 2, _phantom: std::marker::PhantomData}),
                GateRef::new(CosetInterpolationGate::<F, D>{ subgroup_bits:4, degree:6, barycentric_weights: barycentric_weights_fields, _phantom: std::marker::PhantomData }),
                GateRef::new(PoseidonGate::new()),
            ],
            selectors_info: SelectorsInfo {
                selector_indices: vec![0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3],
                groups: vec![0..7, 7..12, 12..15, 15..17],
            },
            quotient_degree_factor: 8,
            num_gate_constraints: 123,
            num_constants: 6,
            num_public_inputs: 198,
            k_is: k_i_fields,
            num_partial_products: 9,
        };

        let condition = builder.add_virtual_bool_target_safe();

        // Unpack inner proof's public inputs.
        let inner_cyclic_proof_with_pis = builder.add_virtual_proof_with_pis(&common_data);
        let inner_cyclic_pis = &inner_cyclic_proof_with_pis.public_inputs;
        let inner_cyclic_initial_block_num = inner_cyclic_pis[0];
        let inner_cyclic_initial_block_hash = AvailHashTarget(inner_cyclic_pis[1..33].try_into().unwrap());
        let inner_cyclic_initial_accumulator = AvailHashTarget(inner_cyclic_pis[33..65].try_into().unwrap());
        let inner_cyclic_latest_block_num = inner_cyclic_pis[65];
        let inner_cyclic_latest_block_hash = AvailHashTarget(inner_cyclic_pis[66..98].try_into().unwrap());
        let inner_cyclic_latest_accumulator = AvailHashTarget(inner_cyclic_pis[98..130].try_into().unwrap());

        // Connect our initial values to that of our inner proof. (If there is no inner proof, the
        // initial values will be unconstrained, which is intentional.)
        builder.connect(head_block_num, inner_cyclic_initial_block_num);
        builder.connect_hash(head_block_hash.clone(), inner_cyclic_initial_block_hash);
        builder.connect_hash(initial_accumulator.clone(), inner_cyclic_initial_accumulator);

        // The input values is the previous outputs if we have an inner proof, or the initial values
        // if this is the base case.
        let actual_block_num_in =
            builder.select(condition, inner_cyclic_latest_block_num, head_block_num);
        let actual_block_hash_in =
            builder.select_hash(condition, &inner_cyclic_latest_block_hash, &head_block_hash);
        let actual_accumulator_in =
            builder.select_hash(condition, &inner_cyclic_latest_accumulator, &initial_accumulator);
        builder.connect(current_block_num, actual_block_num_in);
        builder.connect_hash(current_block_hash, actual_block_hash_in);
        builder.connect_hash(current_accumulator, actual_accumulator_in);

        builder.conditionally_verify_cyclic_proof_or_dummy::<C>(
            condition,
            &inner_cyclic_proof_with_pis,
            &common_data,
        )?;

        println!("KJ: building circuit");
        let cyclic_circuit_data = builder.build::<C>();
        println!("KJ: built circuit");

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
        let head_block_hash_val = hex::decode(BLOCK_530508_PARENT_HASH).unwrap();
        let head_block_num_val = 530507;
        let initial_accumulator_val = [0u8; 32];

        let mut pw = PartialWitness::new();
        pw.set_bool_target(condition, false);
        pw.set_encoded_header_target(&encoded_block_input, headers[0].clone());
        pw.set_target(encoded_block_size, F::from_canonical_u64(headers[0].len() as u64));

        let mut initial_pi = Vec::new();
        initial_pi.push(F::from_canonical_u64(head_block_num_val));
        initial_pi.extend(head_block_hash_val.iter().map(|b| F::from_canonical_u64(*b as u64)));
        initial_pi.extend(initial_accumulator_val.iter().map(|b| F::from_canonical_u64(*b as u64)));
        let initial_pi_map = initial_pi.into_iter().enumerate().collect();

        pw.set_proof_with_pis_target::<C, D>(
            &inner_cyclic_proof_with_pis,
            &cyclic_base_proof(
                &common_data,
                &cyclic_circuit_data.verifier_only,
                initial_pi_map,
            ),
        );
        pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);

        let mut timing1 = TimingTree::new("proof1 proof gen", Level::Info);
        println!("creating base proof");
        let proof1 = prove::<F, C, D>(&cyclic_circuit_data.prover_only, &cyclic_circuit_data.common, pw, &mut timing1)?;
        println!("created base proof");
        timing1.print();

        check_cyclic_proof_verifier_data(
            &proof1,
            &cyclic_circuit_data.verifier_only,
            &cyclic_circuit_data.common,
        )?;

        cyclic_circuit_data.verify(proof1.clone())?;

        // 1st recursive layer.
        let mut pw = PartialWitness::new();
        pw.set_bool_target(condition, true);
        pw.set_encoded_header_target(&encoded_block_input, headers[1].clone());
        pw.set_target(encoded_block_size, F::from_canonical_u64(headers[1].len() as u64));
        pw.set_proof_with_pis_target(&inner_cyclic_proof_with_pis, &proof1);
        pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);
        let mut timing2 = TimingTree::new("proof1 proof gen", Level::Info);
        println!("creating 1st recursive proof");
        let proof2 = prove::<F, C, D>(&cyclic_circuit_data.prover_only, &cyclic_circuit_data.common, pw, &mut timing2)?;
        println!("created 1st recursive proof");
        timing2.print();
        check_cyclic_proof_verifier_data(
            &proof2,
            &cyclic_circuit_data.verifier_only,
            &cyclic_circuit_data.common,
        )?;
        cyclic_circuit_data.verify(proof2.clone())?;

        // 2nd recursive layer.
        let mut pw = PartialWitness::new();
        pw.set_bool_target(condition, true);
        pw.set_encoded_header_target(&encoded_block_input, headers[2].clone());
        pw.set_target(encoded_block_size, F::from_canonical_u64(headers[2].len() as u64));
        pw.set_proof_with_pis_target(&inner_cyclic_proof_with_pis, &proof2);
        pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);
        let mut timing3 = TimingTree::new("proof1 proof gen", Level::Info);
        println!("creating 2nd recursive proof");
        let proof3 = prove::<F, C, D>(&cyclic_circuit_data.prover_only, &cyclic_circuit_data.common, pw, &mut timing3)?;
        println!("created 2nd recursive proof");
        timing3.print();
        check_cyclic_proof_verifier_data(
            &proof3,
            &cyclic_circuit_data.verifier_only,
            &cyclic_circuit_data.common,
        )?;

        println!("proof public inputs: {:?}", proof3.public_inputs.iter().map(|x| x.to_canonical_u64()).collect::<Vec<_>>());

        // TODO: Verify that the proof correctly computes a repeated hash.
        cyclic_circuit_data.verify(proof3)
    }
}