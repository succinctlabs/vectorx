use itertools::Itertools;
use plonky2::gates::selectors::SelectorsInfo;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::plonk::circuit_data::VerifierOnlyCircuitData;
use plonky2::{
    field::extension::Extendable,
    fri::{reduction_strategies::FriReductionStrategy, FriConfig, FriParams},
    gates::{
        arithmetic_base::ArithmeticGate, arithmetic_extension::ArithmeticExtensionGate,
        base_sum::BaseSumGate, constant::ConstantGate, coset_interpolation::CosetInterpolationGate,
        exponentiation::ExponentiationGate, gate::GateRef,
        multiplication_extension::MulExtensionGate, noop::NoopGate, poseidon::PoseidonGate,
        poseidon_mds::PoseidonMdsGate, public_input::PublicInputGate,
        random_access::RandomAccessGate, reducing::ReducingGate,
        reducing_extension::ReducingExtensionGate,
    },
    hash::hash_types::RichField,
    iop::target::{BoolTarget, Target},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CommonCircuitData, VerifierCircuitTarget},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputsTarget,
    },
};
use plonky2x::{hash::blake2::blake2b::blake2b, num::u32::gates::add_many_u32::U32AddManyGate};

use crate::utils::MAX_HEADER_SIZE;
use crate::{
    decoder::CircuitBuilderHeaderDecoder,
    utils::{
        AvailHashTarget, CircuitBuilderUtils, EncodedHeaderTarget, CHUNK_128_BYTES, HASH_SIZE,
    },
};

pub struct PublicInputsElements {
    pub initial_block_hash: AvailHashTarget,
    pub initial_block_num: Target,
    pub initial_data_root_accumulator: AvailHashTarget,
    pub latest_block_hash: AvailHashTarget,
    pub latest_block_num: Target,
    pub latest_data_root_accumulator: AvailHashTarget,
}

pub trait CircuitBuilderHeaderVerification<F: RichField + Extendable<D>, const D: usize> {
    fn verify_header(
        &mut self,
        encoded_header: &EncodedHeaderTarget,
        encoded_header_size: Target,
        parent_block_num: Target,
        parent_hash: &AvailHashTarget,
        data_root_acc: &AvailHashTarget,
    );

    fn verify_header_ivc<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
    ) -> (
        BoolTarget,
        EncodedHeaderTarget,
        Target,
        VerifierCircuitTarget,
        ProofWithPublicInputsTarget<D>,
    )
    where
        C::Hasher: AlgebraicHasher<F>;

    fn verify_header_ivc_cd(&mut self) -> CommonCircuitData<F, D>;

    fn verify_header_ivc_vd<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
    ) -> VerifierOnlyCircuitData<C, D>
    where
        C::Hasher: AlgebraicHasher<F>;

    fn parse_public_inputs(&mut self, public_inputs: &[Target]) -> PublicInputsElements;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHeaderVerification<F, D>
    for CircuitBuilder<F, D>
{
    fn verify_header(
        &mut self,
        encoded_header: &EncodedHeaderTarget,
        encoded_header_size: Target,
        parent_block_num: Target,
        parent_hash_target: &AvailHashTarget,
        data_root_acc: &AvailHashTarget,
    ) {
        // Calculate the hash for the current header
        let header_hasher = blake2b::<F, D, MAX_HEADER_SIZE, HASH_SIZE>(self);

        // Input the encoded header bytes into the hasher
        for i in 0..MAX_HEADER_SIZE {
            // Need to split the bytes into bits
            let mut bits = self.split_le(encoded_header.header_bytes[i], 8);

            // Needs to be in bit big endian order for the EDDSA verification circuit
            bits.reverse();
            for (j, bit) in bits.iter().enumerate().take(8) {
                self.connect(header_hasher.message[i * 8 + j].target, bit.target);
            }
        }

        self.connect(header_hasher.message_len, encoded_header_size);

        // Convert the digest (vector of bits) to bytes
        let mut header_hash_bytes = Vec::new();
        for byte_chunk in header_hasher.digest.chunks(8) {
            let byte = self.le_sum(byte_chunk.to_vec().iter().rev());
            self.register_public_input(byte);
            header_hash_bytes.push(byte);
        }

        // Get the decoded_header object to retrieve the block numbers and parent hashes
        let decoded_header = self.decode_header(
            encoded_header,
            AvailHashTarget(header_hash_bytes.as_slice().try_into().unwrap()),
        );

        // Verify that this header's block number is one greater than the previous header's block number
        let one = self.one();
        let expected_block_num = self.add(parent_block_num, one);
        self.connect(expected_block_num, decoded_header.block_number);
        self.register_public_input(decoded_header.block_number);

        // Verify that the parent hash is equal to the decoded parent hash
        self.connect_avail_hash(parent_hash_target.clone(), decoded_header.parent_hash);

        // Calculate the hash of the extracted fields and add them into the accumulator
        let data_root_acc_hasher = blake2b::<F, D, CHUNK_128_BYTES, HASH_SIZE>(self);

        let mut hasher_idx = 0;
        // Input the accumulator
        for hash_byte in data_root_acc.0.iter() {
            let mut bits = self.split_le(*hash_byte, 8);

            bits.reverse();
            assert!(bits.len() == 8);
            for bit in bits.iter() {
                self.connect(data_root_acc_hasher.message[hasher_idx].target, bit.target);
                hasher_idx += 1;
            }
        }

        // Input the data root
        for byte in decoded_header.data_root.0.iter() {
            let mut bits = self.split_le(*byte, 8);

            bits.reverse();
            assert!(bits.len() == 8);
            for bit in bits.iter() {
                self.connect(data_root_acc_hasher.message[hasher_idx].target, bit.target);
                hasher_idx += 1;
            }
        }

        for i in hasher_idx..CHUNK_128_BYTES * 8 {
            let zero = self.zero();
            self.connect(data_root_acc_hasher.message[i].target, zero);
        }

        let input_len = self.constant(F::from_canonical_usize(hasher_idx / 8));
        self.connect(data_root_acc_hasher.message_len, input_len);

        for byte_chunk in data_root_acc_hasher.digest.chunks(8) {
            let byte = self.le_sum(byte_chunk.to_vec().iter().rev());
            self.register_public_input(byte);
        }
    }

    fn verify_header_ivc<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
    ) -> (
        BoolTarget,
        EncodedHeaderTarget,
        Target,
        VerifierCircuitTarget,
        ProofWithPublicInputsTarget<D>,
    )
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        // False for the base case, true otherwise
        let condition = self.add_virtual_bool_target_safe();

        let common_data = self.verify_header_ivc_cd();

        // Unpack inner proof's public inputs.
        let previous_header_verification_proof_with_pis =
            self.add_virtual_proof_with_pis(&common_data);
        let previous_proof_elements =
            self.parse_public_inputs(&previous_header_verification_proof_with_pis.public_inputs);

        // Set the initial elements to be public inputs
        self.register_public_inputs(&previous_proof_elements.initial_block_hash.0);
        self.register_public_input(previous_proof_elements.initial_block_num);
        self.register_public_inputs(&previous_proof_elements.initial_data_root_accumulator.0);

        let previous_block_hash = self.random_access_avail_hash(
            condition.target,
            vec![
                previous_proof_elements.initial_block_hash,
                previous_proof_elements.latest_block_hash,
            ],
        );

        let previous_block_num = self.random_access(
            condition.target,
            vec![
                previous_proof_elements.initial_block_num,
                previous_proof_elements.latest_block_num,
            ],
        );

        let previous_data_root_accumulator = self.random_access_avail_hash(
            condition.target,
            vec![
                previous_proof_elements.initial_data_root_accumulator,
                previous_proof_elements.latest_data_root_accumulator,
            ],
        );

        // Create inputs for the current encoded block;
        let encoded_block_input = self.add_virtual_encoded_header_target_safe();
        let encoded_block_size = self.add_virtual_target();

        self.verify_header(
            &encoded_block_input,
            encoded_block_size,
            previous_block_num,
            &previous_block_hash,
            &previous_data_root_accumulator,
        );

        let verifier_data_target = self.add_verifier_data_public_inputs();

        self.conditionally_verify_cyclic_proof_or_dummy::<C>(
            condition,
            &previous_header_verification_proof_with_pis,
            &common_data,
        )
        .expect("generation of cyclic proof circuit failed");

        (
            condition,
            encoded_block_input,
            encoded_block_size,
            verifier_data_target,
            previous_header_verification_proof_with_pis,
        )
    }

    fn verify_header_ivc_cd(&mut self) -> CommonCircuitData<F, D> {
        let k_is = vec![
            1,
            7,
            49,
            343,
            2401,
            16807,
            117649,
            823543,
            5764801,
            40353607,
            282475249,
            1977326743,
            13841287201,
            96889010407,
            678223072849,
            4747561509943,
            33232930569601,
            232630513987207,
            1628413597910449,
            11398895185373143,
            79792266297612001,
            558545864083284007,
            3909821048582988049,
            8922003270666332022,
            7113790686420571191,
            12903046666114829695,
            16534350385145470581,
            5059988279530788141,
            16973173887300932666,
            8131752794619022736,
            1582037354089406189,
            11074261478625843323,
            3732854072722565977,
            7683234439643377518,
            16889152938674473984,
            7543606154233811962,
            15911754940807515092,
            701820169165099718,
            4912741184155698026,
            15942444219675301861,
            916645121239607101,
            6416515848677249707,
            8022122801911579307,
            814627405137302186,
            5702391835961115302,
            3023254712898638472,
            2716038920875884983,
            565528376716610560,
            3958698637016273920,
            9264146389699333119,
            9508792519651578870,
            11221315429317299127,
            4762231727562756605,
            14888878023524711914,
            11988425817600061793,
            10132004445542095267,
            15583798910550913906,
            16852872026783475737,
            7289639770996824233,
            14133990258148600989,
            6704211459967285318,
            10035992080941828584,
            14911712358349047125,
            12148266161370408270,
            11250886851934520606,
            4969231685883306958,
            16337877731768564385,
            3684679705892444769,
            7346013871832529062,
            14528608963998534792,
            9466542400916821939,
            10925564598174000610,
            2691975909559666986,
            397087297503084581,
            2779611082521592067,
            1010533508236560148,
            7073734557655921036,
            12622653764762278610,
            14571600075677612986,
            9767480182670369297,
        ];
        let k_i_fields = k_is
            .iter()
            .map(|x| F::from_canonical_u64(*x))
            .collect::<Vec<_>>();

        let barycentric_weights = vec![
            17293822565076172801,
            18374686475376656385,
            18446744069413535745,
            281474976645120,
            17592186044416,
            18446744069414584577,
            18446744000695107601,
            18446744065119617025,
            1152921504338411520,
            72057594037927936,
            18446744069415632897,
            18446462594437939201,
            18446726477228539905,
            18446744069414584065,
            68719476720,
            4294967296,
        ];
        let barycentric_weights_fields = barycentric_weights
            .iter()
            .map(|x| F::from_noncanonical_u64(*x))
            .collect::<Vec<_>>();

        CommonCircuitData::<F, D> {
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
                    num_query_rounds: 28,
                },
            },
            fri_params: FriParams {
                config: FriConfig {
                    rate_bits: 3,
                    cap_height: 4,
                    proof_of_work_bits: 16,
                    reduction_strategy: FriReductionStrategy::ConstantArityBits(4, 5),
                    num_query_rounds: 28,
                },
                hiding: false,
                degree_bits: 20,
                reduction_arity_bits: vec![4, 4, 4, 4],
            },
            gates: vec![
                GateRef::new(NoopGate {}),
                GateRef::new(ConstantGate { num_consts: 2 }),
                GateRef::new(PoseidonMdsGate::new()),
                GateRef::new(PublicInputGate {}),
                GateRef::new(BaseSumGate::<2>::new(32)),
                GateRef::new(BaseSumGate::<2>::new(63)),
                GateRef::new(RandomAccessGate {
                    bits: 1,
                    num_copies: 20,
                    num_extra_constants: 0,
                    _phantom: std::marker::PhantomData,
                }),
                GateRef::new(ReducingExtensionGate::new(32)),
                GateRef::new(ReducingGate { num_coeffs: 43 }),
                GateRef::new(ArithmeticExtensionGate { num_ops: 10 }),
                GateRef::new(ArithmeticGate { num_ops: 20 }),
                GateRef::new(MulExtensionGate { num_ops: 13 }),
                GateRef::new(RandomAccessGate {
                    bits: 2,
                    num_copies: 13,
                    num_extra_constants: 2,
                    _phantom: std::marker::PhantomData,
                }),
                GateRef::new(ExponentiationGate {
                    num_power_bits: 66,
                    _phantom: std::marker::PhantomData,
                }),
                GateRef::new(U32AddManyGate {
                    num_addends: 3,
                    num_ops: 5,
                    _phantom: std::marker::PhantomData,
                }),
                GateRef::new(RandomAccessGate {
                    bits: 4,
                    num_copies: 4,
                    num_extra_constants: 2,
                    _phantom: std::marker::PhantomData,
                }),
                GateRef::new(CosetInterpolationGate::<F, D> {
                    subgroup_bits: 4,
                    degree: 6,
                    barycentric_weights: barycentric_weights_fields,
                    _phantom: std::marker::PhantomData,
                }),
                GateRef::new(RandomAccessGate {
                    bits: 5,
                    num_copies: 2,
                    num_extra_constants: 2,
                    _phantom: std::marker::PhantomData,
                }),
                GateRef::new(PoseidonGate::new()),
            ],
            selectors_info: SelectorsInfo {
                selector_indices: vec![0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 2, 2, 2, 3, 3, 4],
                groups: vec![0..7, 7..13, 13..16, 16..18, 18..19],
            },
            quotient_degree_factor: 8,
            num_gate_constraints: 123,
            num_constants: 7,
            num_public_inputs: 198,
            k_is: k_i_fields,
            num_partial_products: 9,
            num_lookup_polys: 0,
            num_lookup_selectors: 0,
            luts: vec![],
        }
    }

    fn verify_header_ivc_vd<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
    ) -> VerifierOnlyCircuitData<C, D>
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        VerifierOnlyCircuitData {
            constants_sigmas_cap: MerkleCap(vec![
                HashOut {
                    elements: [
                        F::from_canonical_u64(6893720534254420556),
                        F::from_canonical_u64(9869054201206402635),
                        F::from_canonical_u64(3358764550157965550),
                        F::from_canonical_u64(6675137039753538583),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(9318131052852035840),
                        F::from_canonical_u64(14659927684923102740),
                        F::from_canonical_u64(3784472940063110559),
                        F::from_canonical_u64(16784635435692189864),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(11397923598101180517),
                        F::from_canonical_u64(3443949465444487309),
                        F::from_canonical_u64(310356847864724848),
                        F::from_canonical_u64(13458374281624371795),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(18085161840372940135),
                        F::from_canonical_u64(7892209763543399901),
                        F::from_canonical_u64(6082261755853580677),
                        F::from_canonical_u64(1568884689200641943),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(2590041485672371550),
                        F::from_canonical_u64(3356466597987899279),
                        F::from_canonical_u64(5531330291860805498),
                        F::from_canonical_u64(14582277832861805436),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(2734120159474797714),
                        F::from_canonical_u64(1691743372901094773),
                        F::from_canonical_u64(5382663207442631785),
                        F::from_canonical_u64(3511306326001178864),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(3696427309811613410),
                        F::from_canonical_u64(16540559545728973044),
                        F::from_canonical_u64(16141756920172504578),
                        F::from_canonical_u64(6217238375257484964),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(17293630180144692949),
                        F::from_canonical_u64(8414769978449101600),
                        F::from_canonical_u64(3443174534402031709),
                        F::from_canonical_u64(16391976540590050956),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(8068533027332123430),
                        F::from_canonical_u64(1314530871443210915),
                        F::from_canonical_u64(2940206156759058344),
                        F::from_canonical_u64(3822058680787933664),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(17369262077311455804),
                        F::from_canonical_u64(10215356053836114628),
                        F::from_canonical_u64(129878469886448921),
                        F::from_canonical_u64(16654904064191771284),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(18265920119281374126),
                        F::from_canonical_u64(9725380710897336879),
                        F::from_canonical_u64(4266829456287036759),
                        F::from_canonical_u64(8411062113742938734),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(16053311469103636805),
                        F::from_canonical_u64(17571710357177248136),
                        F::from_canonical_u64(16078712453291616059),
                        F::from_canonical_u64(12047202881998658277),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(8563327907016317907),
                        F::from_canonical_u64(17772250373900712080),
                        F::from_canonical_u64(16928341334553613595),
                        F::from_canonical_u64(9201354879858974391),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(10160488212967830942),
                        F::from_canonical_u64(6610201163933124212),
                        F::from_canonical_u64(15616704182486088003),
                        F::from_canonical_u64(2872964065949267424),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(14521846623774124579),
                        F::from_canonical_u64(13070295758220160172),
                        F::from_canonical_u64(16086946402741816526),
                        F::from_canonical_u64(14746700217644244250),
                    ],
                },
                HashOut {
                    elements: [
                        F::from_canonical_u64(1526764342355135675),
                        F::from_canonical_u64(2246058144923642203),
                        F::from_canonical_u64(9172708044764903231),
                        F::from_canonical_u64(14524488702222024842),
                    ],
                },
            ]),
            circuit_digest: HashOut {
                elements: [
                    F::from_canonical_u64(7368954165088992480),
                    F::from_canonical_u64(1272539449903483734),
                    F::from_canonical_u64(15167093575070754927),
                    F::from_canonical_u64(3216329643681779426),
                ],
            },
        }
    }

    fn parse_public_inputs(&mut self, public_inputs: &[Target]) -> PublicInputsElements {
        let mut public_inputs_iter = public_inputs.iter();

        PublicInputsElements {
            initial_block_hash: AvailHashTarget(
                public_inputs_iter
                    .by_ref()
                    .take(HASH_SIZE)
                    .copied()
                    .collect_vec()
                    .as_slice()
                    .try_into()
                    .unwrap(),
            ),
            initial_block_num: *public_inputs_iter.by_ref().take(1).collect_vec()[0],
            initial_data_root_accumulator: AvailHashTarget(
                public_inputs_iter
                    .by_ref()
                    .take(HASH_SIZE)
                    .copied()
                    .collect_vec()
                    .as_slice()
                    .try_into()
                    .unwrap(),
            ),
            latest_block_hash: AvailHashTarget(
                public_inputs_iter
                    .by_ref()
                    .take(HASH_SIZE)
                    .copied()
                    .collect_vec()
                    .as_slice()
                    .try_into()
                    .unwrap(),
            ),
            latest_block_num: *public_inputs_iter.by_ref().take(1).collect_vec()[0],
            latest_data_root_accumulator: AvailHashTarget(
                public_inputs_iter
                    .take(HASH_SIZE)
                    .by_ref()
                    .copied()
                    .collect_vec()
                    .as_slice()
                    .try_into()
                    .unwrap(),
            ),
        }
    }
}

#[cfg(test)]
pub mod tests {
    use crate::{
        subchain_verification::CircuitBuilderHeaderVerification,
        testing_utils::tests::{BLOCK_HASHES, ENCODED_HEADERS, HEAD_BLOCK_NUM},
        utils::WitnessEncodedHeader,
    };
    use anyhow::Result;
    use log::Level;
    use plonky2::field::types::Field;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
            proof::ProofWithPublicInputs,
            prover::prove,
        },
        recursion::{
            cyclic_recursion::check_cyclic_proof_verifier_data, dummy_circuit::cyclic_base_proof,
        },
        util::timing::TimingTree,
    };

    const D: usize = 2;
    type C = PoseidonGoldilocksConfig;
    type F = <C as GenericConfig<D>>::F;

    pub fn retrieve_subchain_verification_proof() -> Result<ProofWithPublicInputs<F, C, D>> {
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let common_data = builder.verify_header_ivc_cd();

        let (
            condition,
            encoded_block_input,
            encoded_block_size,
            verifier_data_target,
            previous_header_verification_proof_with_pis,
        ) = builder.verify_header_ivc::<C>();

        let cyclic_circuit_data = builder.build::<C>();

        let initial_block_hash_val = hex::decode(BLOCK_HASHES[0]).unwrap();
        let initial_block_num_val = HEAD_BLOCK_NUM;
        let initial_data_root_accumulator_val = [1u8; 32];

        let mut use_prev_proof = false;
        let mut prev_proof: Option<ProofWithPublicInputs<F, C, D>> = None;
        let mut header_num = initial_block_num_val + 1;

        // The first encoded header is the HEAD header.  We assume that is already verified.
        for header in ENCODED_HEADERS[1..].iter() {
            println!("Generating proof for header: {}", header_num);
            let mut pw = PartialWitness::new();
            let header_bytes = hex::decode(header).expect("Expect a valid hex string");
            pw.set_bool_target(condition, use_prev_proof);
            pw.set_encoded_header_target(&encoded_block_input, header_bytes.clone());
            pw.set_target(
                encoded_block_size,
                F::from_canonical_u64(header_bytes.len() as u64),
            );

            if !use_prev_proof {
                let mut initial_pi = Vec::new();
                initial_pi.extend(
                    initial_block_hash_val
                        .iter()
                        .map(|b| F::from_canonical_u64(*b as u64)),
                );
                initial_pi.push(F::from_canonical_u64(initial_block_num_val.into()));
                initial_pi.extend(
                    initial_data_root_accumulator_val
                        .iter()
                        .map(|b| F::from_canonical_u64(*b as u64)),
                );
                let initial_pi_map = initial_pi.into_iter().enumerate().collect();

                let base_proof = cyclic_base_proof(
                    &common_data,
                    &cyclic_circuit_data.verifier_only,
                    initial_pi_map,
                );

                pw.set_proof_with_pis_target::<C, D>(
                    &previous_header_verification_proof_with_pis,
                    &base_proof,
                );
            } else {
                pw.set_proof_with_pis_target::<C, D>(
                    &previous_header_verification_proof_with_pis,
                    &prev_proof.expect("some be a Some value"),
                );
            }

            pw.set_verifier_data_target(&verifier_data_target, &cyclic_circuit_data.verifier_only);

            let mut timing1 = TimingTree::new("proof gen", Level::Info);
            let proof = prove::<F, C, D>(
                &cyclic_circuit_data.prover_only,
                &cyclic_circuit_data.common,
                pw,
                &mut timing1,
            )?;
            timing1.print();

            check_cyclic_proof_verifier_data(
                &proof,
                &cyclic_circuit_data.verifier_only,
                &cyclic_circuit_data.common,
            )?;

            cyclic_circuit_data.verify(proof.clone())?;
            println!("proof for block {} is valid", header_num);

            prev_proof = Some(proof);
            use_prev_proof = true;
            header_num += 1;
        }

        Ok(prev_proof.expect("prev_proof must be a Some value"))
    }

    #[test]
    fn test_verify_subchain() -> Result<()> {
        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let proof = retrieve_subchain_verification_proof();

        if proof.is_err() {
            Err(anyhow::anyhow!("proof generation failed"))
        } else {
            Ok(())
        }
    }
}
