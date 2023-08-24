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

#[derive(Debug)]
pub struct PublicInputsElements {
    pub initial_block_hash: [u8; HASH_SIZE],
    pub initial_block_num: u32,
    pub initial_data_root_accumulator: [u8; HASH_SIZE],
    pub latest_block_hash: [u8; HASH_SIZE],
    pub latest_block_num: u32,
    pub latest_data_root_accumulator: [u8; HASH_SIZE],
}

pub(crate) fn verify_header_ivc_cd<F: RichField + Extendable<D>, const D: usize>(
) -> CommonCircuitData<F, D> {
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

pub(crate) fn verify_header_ivc_vd<
    C: GenericConfig<D, F = F> + 'static,
    F: RichField + Extendable<D>,
    const D: usize,
>() -> VerifierOnlyCircuitData<C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    VerifierOnlyCircuitData {
        constants_sigmas_cap: MerkleCap(vec![
            HashOut {
                elements: [
                    F::from_canonical_u64(14279925247335401071),
                    F::from_canonical_u64(3583580480101461931),
                    F::from_canonical_u64(16536002908860857775),
                    F::from_canonical_u64(6379011898590097254),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(8732164097790799892),
                    F::from_canonical_u64(6151513101891070743),
                    F::from_canonical_u64(1404140543879842872),
                    F::from_canonical_u64(1186760377589587695),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(4659367829642659994),
                    F::from_canonical_u64(12964625556265386253),
                    F::from_canonical_u64(15874664631145335428),
                    F::from_canonical_u64(792879913970014316),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(5060056232339645809),
                    F::from_canonical_u64(7579074518106734870),
                    F::from_canonical_u64(13396451108061219118),
                    F::from_canonical_u64(6431550535925716133),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(4772976151813849053),
                    F::from_canonical_u64(5019224891998960239),
                    F::from_canonical_u64(856022066557676709),
                    F::from_canonical_u64(13050201476718469703),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(2487290536140898141),
                    F::from_canonical_u64(4174181341619288417),
                    F::from_canonical_u64(14982911265678359885),
                    F::from_canonical_u64(13893519756166789652),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(12757396429388144395),
                    F::from_canonical_u64(11991974417901135198),
                    F::from_canonical_u64(13917361533990408017),
                    F::from_canonical_u64(14414676336513742857),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(13525073521029784592),
                    F::from_canonical_u64(12386677733145181517),
                    F::from_canonical_u64(14957654821266202593),
                    F::from_canonical_u64(8110540373850920504),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(8132364512809958997),
                    F::from_canonical_u64(812601146402104015),
                    F::from_canonical_u64(18271575082902528502),
                    F::from_canonical_u64(16551916704520327064),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(14221641715425497611),
                    F::from_canonical_u64(12623299214957053833),
                    F::from_canonical_u64(13078306607384483897),
                    F::from_canonical_u64(15630241381614775121),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(9511367709381189559),
                    F::from_canonical_u64(1864191245331275275),
                    F::from_canonical_u64(17658721473363737448),
                    F::from_canonical_u64(7877250233373704416),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(7066539818341181594),
                    F::from_canonical_u64(15011388141196267991),
                    F::from_canonical_u64(5040531198568509574),
                    F::from_canonical_u64(10697356820270951727),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(2293756880236203641),
                    F::from_canonical_u64(2665884223398335517),
                    F::from_canonical_u64(13736438034327644166),
                    F::from_canonical_u64(5669853307172626816),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(2856730570195234907),
                    F::from_canonical_u64(18316577759665185535),
                    F::from_canonical_u64(16427081493093691001),
                    F::from_canonical_u64(4647791340002963359),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(17467181932095298266),
                    F::from_canonical_u64(10201010735740812763),
                    F::from_canonical_u64(7898132404335443927),
                    F::from_canonical_u64(14480769791743578824),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(5245849465894255747),
                    F::from_canonical_u64(8864305202869869746),
                    F::from_canonical_u64(5467314423136200158),
                    F::from_canonical_u64(3072797568720766929),
                ],
            },
        ]),
        circuit_digest: HashOut {
            elements: [
                F::from_canonical_u64(18220935880225098234),
                F::from_canonical_u64(9421693311425457359),
                F::from_canonical_u64(5950288396293546789),
                F::from_canonical_u64(5499183684015304306),
            ],
        },
    }
}

fn parse_public_inputs<
    C: GenericConfig<D, F = F> + 'static,
    F: RichField + Extendable<D>,
    const D: usize,
>(
    public_inputs: Vec<F>,
) -> PublicInputsElements
where
    C::Hasher: AlgebraicHasher<F>,
{
    let vd = verify_header_ivc_vd::<C, F, D>();

    // 4 hashes and 2 block numbers and the circuit digest and sigma contants cap
    let public_inputs_len = 4 * HASH_SIZE + 2;

    assert!(
        public_inputs.len()
            == public_inputs_len
                + vd.circuit_digest.elements.len()
                + vd.constants_sigmas_cap
                    .0
                    .iter()
                    .map(|x| x.elements.len())
                    .sum::<usize>()
    );

    let canonical_public_inputs = public_inputs
        .iter()
        .take(public_inputs_len)
        .map(|x| {
            u32::try_from(F::to_canonical_u64(x)).expect("element in public inputs is not a u32")
        })
        .collect_vec();
    let mut public_inputs_iter = canonical_public_inputs.iter();

    PublicInputsElements {
        initial_block_hash:
                public_inputs_iter
                .by_ref()
                .take(HASH_SIZE)
                .map(|x| u8::try_from(*x).expect("element in public inputs is not a u8"))
                .collect_vec()
                .as_slice()
                .try_into()
                .expect("can't take HASH_SIZE elements from public inputs for initial block hash"),
        initial_block_num: *public_inputs_iter.by_ref().take(1).collect_vec()[0],
        initial_data_root_accumulator: public_inputs_iter
                .by_ref()
                .take(HASH_SIZE)
                .map(|x| u8::try_from(*x).expect("element in public inputs is not a u8"))
                .collect_vec()
                .as_slice()
                .try_into()
                .expect("can't take HASH_SIZE elements from public inputs for initial data root accumulator"),
        latest_block_hash: public_inputs_iter
                .by_ref().
                take(HASH_SIZE)
                .map(|x| u8::try_from(*x).expect("element in public inputs is not a u8"))
                .collect_vec()
                .as_slice()
                .try_into()
                .expect("can't take HASH_SIZE elements from public inputs for latest block hash"),
        latest_block_num: *public_inputs_iter.by_ref().take(1).collect_vec()[0],
        latest_data_root_accumulator: public_inputs_iter
                .by_ref()
                .take(HASH_SIZE)
                .map(|x| u8::try_from(*x).expect("element in public inputs is not a u8"))
                .collect_vec()
                .as_slice()
                .try_into()
                .expect("can't take HASH_SIZE elements from public inputs for latest data root accumulator"),
    }
}

pub struct PublicInputsElementsTarget {
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

    fn parse_public_inputs(&mut self, public_inputs: &[Target]) -> PublicInputsElementsTarget;
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

        let common_data = verify_header_ivc_cd();

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

    fn parse_public_inputs(&mut self, public_inputs: &[Target]) -> PublicInputsElementsTarget {
        let mut public_inputs_iter = public_inputs.iter();

        PublicInputsElementsTarget {
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
        subchain_verification::{
            parse_public_inputs, verify_header_ivc_cd, verify_header_ivc_vd,
            CircuitBuilderHeaderVerification,
        },
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

        let common_data = verify_header_ivc_cd();
        let verifier_data = verify_header_ivc_vd();

        let (
            condition,
            encoded_block_input,
            encoded_block_size,
            verifier_data_target,
            previous_header_verification_proof_with_pis,
        ) = builder.verify_header_ivc::<C>();

        let cyclic_circuit_data = builder.build::<C>();

        // Assert that the circuit's common data nd verifier data matches what is expected
        assert_eq!(common_data, cyclic_circuit_data.common);

        assert_eq!(verifier_data, cyclic_circuit_data.verifier_only,);

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

        let final_proof = prev_proof.expect("prev_proof must be a Some value");

        // Verify all of the final proof's public inputs are expected.
        let proof_pis = parse_public_inputs::<C, F, D>(final_proof.clone().public_inputs);

        println!("proof_pis is {:?}", proof_pis);

        assert!(proof_pis.initial_block_hash == hex::decode(BLOCK_HASHES[0]).unwrap().as_slice());
        assert!(proof_pis.initial_block_num == HEAD_BLOCK_NUM);
        assert!(proof_pis.initial_data_root_accumulator == [1u8; 32]);
        assert!(
            proof_pis.latest_block_hash
                == hex::decode(BLOCK_HASHES.last().unwrap())
                    .unwrap()
                    .as_slice()
        );
        assert!(proof_pis.latest_block_num == HEAD_BLOCK_NUM + ENCODED_HEADERS.len() as u32 - 1);
        assert!(
            proof_pis.latest_data_root_accumulator
                == hex::decode("b7200702f3bd78ab4f99d1877ff923a706f10de475aeda08f0418bc481c0c4d4")
                    .unwrap()
                    .as_slice()
        );

        Ok(final_proof)
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
