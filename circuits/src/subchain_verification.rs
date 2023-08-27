use itertools::Itertools;
use plonky2::gates::selectors::SelectorsInfo;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::plonk::circuit_data::{CircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData};
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
        circuit_data::{CircuitConfig, CommonCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputsTarget,
    },
};
use plonky2x::{
    frontend::hash::blake2::blake2b::blake2b,
    frontend::num::u32::gates::add_many_u32::U32AddManyGate,
};

use crate::header::{
    process_large_header_cd, process_large_header_vd, process_small_header_cd,
    process_small_header_vd, CircuitBuilderHeader,
};
use crate::utils::{AvailHashTarget, CircuitBuilderUtils, CHUNK_128_BYTES, HASH_SIZE};

struct HeaderIVCTargets<const D: usize> {
    ivc_base_case: BoolTarget,
    ivc_prev_proof: ProofWithPublicInputsTarget<D>,
    is_small_header: BoolTarget,
    small_header_proof: ProofWithPublicInputsTarget<D>,
    large_header_proof: ProofWithPublicInputsTarget<D>,
    verifier_circuit_target: VerifierCircuitTarget,
}

fn create_header_ivc_circuit<
    C: GenericConfig<D, F = F> + 'static,
    F: RichField + Extendable<D>,
    const D: usize,
>() -> (HeaderIVCTargets<D>, CircuitData<F, C, D>)
where
    C::Hasher: AlgebraicHasher<F>,
{
    // Build the IVC circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut header_ivc_builder = CircuitBuilder::<F, D>::new(config);

    let header_ivc_data_cd = verify_header_ivc_cd();
    let header_ivc_data_vd = verify_header_ivc_vd::<C, F, D>();

    let ivc_base_case = header_ivc_builder.add_virtual_bool_target_safe();
    let ivc_prev_proof = header_ivc_builder.add_virtual_proof_with_pis(&header_ivc_data_cd);
    let is_small_header = header_ivc_builder.add_virtual_bool_target_safe();
    let small_header_proof =
        header_ivc_builder.add_virtual_proof_with_pis(&process_small_header_cd());
    let large_header_proof =
        header_ivc_builder.add_virtual_proof_with_pis(&process_large_header_cd());

    let verifier_circuit_target = header_ivc_builder.verify_header_ivc::<C>(
        ivc_base_case,
        &ivc_prev_proof,
        is_small_header,
        &small_header_proof,
        &large_header_proof,
    );

    let header_ivc_data = header_ivc_builder.build::<C>();

    assert_eq!(header_ivc_data_cd, header_ivc_data.common);
    assert_eq!(header_ivc_data_vd, header_ivc_data.verifier_only);

    (
        HeaderIVCTargets {
            ivc_base_case,
            ivc_prev_proof,
            is_small_header,
            small_header_proof,
            large_header_proof,
            verifier_circuit_target,
        },
        header_ivc_data,
    )
}
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
            degree_bits: 15,
            reduction_arity_bits: vec![4, 4, 4],
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
                    F::from_canonical_u64(13719139148739964809),
                    F::from_canonical_u64(3985397077093140875),
                    F::from_canonical_u64(773757932482375232),
                    F::from_canonical_u64(8637618966119583773),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(2656020757760353093),
                    F::from_canonical_u64(14686348016219292686),
                    F::from_canonical_u64(17770147950708789167),
                    F::from_canonical_u64(1850510006545369410),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(1090170580786137082),
                    F::from_canonical_u64(12030120322367455319),
                    F::from_canonical_u64(6693889947032175223),
                    F::from_canonical_u64(4742544349390995199),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(5967148472721089790),
                    F::from_canonical_u64(521240221714532128),
                    F::from_canonical_u64(15113222525508286174),
                    F::from_canonical_u64(18101070528724371009),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(2179402085063084374),
                    F::from_canonical_u64(1324738038116675393),
                    F::from_canonical_u64(15639935564811592268),
                    F::from_canonical_u64(14110330424342799321),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(5085493671857677834),
                    F::from_canonical_u64(3163465376487088930),
                    F::from_canonical_u64(446859572954146329),
                    F::from_canonical_u64(562431090586488276),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(633852943748649501),
                    F::from_canonical_u64(14898532295077885214),
                    F::from_canonical_u64(12860999273626228119),
                    F::from_canonical_u64(6450279647528044710),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(16088316488449644138),
                    F::from_canonical_u64(7516367299025720302),
                    F::from_canonical_u64(14612406540018789082),
                    F::from_canonical_u64(309571978577453448),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(11032371094331043424),
                    F::from_canonical_u64(12897008859105511198),
                    F::from_canonical_u64(10280412945954997874),
                    F::from_canonical_u64(4638235353211685583),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(4336604884965786914),
                    F::from_canonical_u64(10521862303181130403),
                    F::from_canonical_u64(8198530657707600836),
                    F::from_canonical_u64(862832117634404501),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(8764447427652359863),
                    F::from_canonical_u64(140806324180441725),
                    F::from_canonical_u64(2124360974791376117),
                    F::from_canonical_u64(1157920850574243235),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(11971173263666324029),
                    F::from_canonical_u64(11626208458821757341),
                    F::from_canonical_u64(12510683023519432739),
                    F::from_canonical_u64(628223843945421854),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(4649190021658144552),
                    F::from_canonical_u64(8769951343905798523),
                    F::from_canonical_u64(2040244381547316143),
                    F::from_canonical_u64(5468458054821461752),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(9446091277615157237),
                    F::from_canonical_u64(11272874009298949758),
                    F::from_canonical_u64(12636611450938436722),
                    F::from_canonical_u64(8361652884955591133),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(17026774536457495032),
                    F::from_canonical_u64(1702526204064302965),
                    F::from_canonical_u64(4668331712793734099),
                    F::from_canonical_u64(6571179310180709525),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(13236748600385133155),
                    F::from_canonical_u64(596261182024546888),
                    F::from_canonical_u64(1586674165004293151),
                    F::from_canonical_u64(16144280193924284642),
                ],
            },
        ]),
        circuit_digest: HashOut {
            elements: [
                F::from_canonical_u64(16839424014964235289),
                F::from_canonical_u64(7920165497178828214),
                F::from_canonical_u64(13857837247028786633),
                F::from_canonical_u64(3825363243085304393),
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
    fn recursive_verify_header<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        small_header: BoolTarget,
        small_header_proof: &ProofWithPublicInputsTarget<D>,
        large_header_proof: &ProofWithPublicInputsTarget<D>,
    ) -> (
        AvailHashTarget,
        Target,
        AvailHashTarget,
        AvailHashTarget,
        AvailHashTarget,
    )
    where
        C::Hasher: AlgebraicHasher<F>;

    fn verify_header_ivc<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        ivc_base_case: BoolTarget,
        ivc_prev_proof: &ProofWithPublicInputsTarget<D>,
        is_small_header: BoolTarget,
        small_header_proof: &ProofWithPublicInputsTarget<D>,
        large_header_proof: &ProofWithPublicInputsTarget<D>,
    ) -> VerifierCircuitTarget
    where
        C::Hasher: AlgebraicHasher<F>;

    fn parse_public_inputs(&mut self, public_inputs: &[Target]) -> PublicInputsElementsTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHeaderVerification<F, D>
    for CircuitBuilder<F, D>
{
    fn recursive_verify_header<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        small_header: BoolTarget,
        small_header_proof: &ProofWithPublicInputsTarget<D>,
        large_header_proof: &ProofWithPublicInputsTarget<D>,
    ) -> (
        AvailHashTarget,
        Target,
        AvailHashTarget,
        AvailHashTarget,
        AvailHashTarget,
    )
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let small_header_vd = process_small_header_vd::<C, F, D>();
        let small_header_cd = process_small_header_cd();
        let small_header_vd_t = self.constant_verifier_data(&small_header_vd);

        self.conditionally_verify_proof_or_dummy::<C>(
            small_header,
            small_header_proof,
            &small_header_vd_t,
            &small_header_cd,
        )
        .expect("Failed in generating small header verification conditional circuit");

        let large_header = self.not(small_header);
        let large_header_vd = process_large_header_vd::<C, F, D>();
        let large_header_cd = process_large_header_cd();
        let large_header_vd_t = self.constant_verifier_data(&large_header_vd);

        self.conditionally_verify_proof_or_dummy::<C>(
            large_header,
            large_header_proof,
            &large_header_vd_t,
            &large_header_cd,
        )
        .expect("Failed in generating header header verification conditional circuit");

        let small_header_public_inputs = self.parse_header_pi(&small_header_proof.public_inputs);

        let large_header_public_inputs = self.parse_header_pi(&large_header_proof.public_inputs);

        let block_hash = self.random_access_avail_hash(
            small_header.target,
            vec![
                large_header_public_inputs.block_hash,
                small_header_public_inputs.block_hash,
            ],
        );

        let block_num = self.random_access(
            small_header.target,
            vec![
                large_header_public_inputs.block_num,
                small_header_public_inputs.block_num,
            ],
        );

        let parent_hash = self.random_access_avail_hash(
            small_header.target,
            vec![
                large_header_public_inputs.parent_hash,
                small_header_public_inputs.parent_hash,
            ],
        );

        let state_root = self.random_access_avail_hash(
            small_header.target,
            vec![
                large_header_public_inputs.state_root,
                small_header_public_inputs.state_root,
            ],
        );

        let data_root = self.random_access_avail_hash(
            small_header.target,
            vec![
                large_header_public_inputs.data_root,
                small_header_public_inputs.data_root,
            ],
        );

        (block_hash, block_num, parent_hash, state_root, data_root)
    }

    fn verify_header_ivc<C: GenericConfig<D, F = F> + 'static>(
        &mut self,
        ivc_base_case: BoolTarget,
        ivc_prev_proof: &ProofWithPublicInputsTarget<D>,
        is_small_header: BoolTarget,
        small_header_proof: &ProofWithPublicInputsTarget<D>,
        large_header_proof: &ProofWithPublicInputsTarget<D>,
    ) -> VerifierCircuitTarget
    where
        C::Hasher: AlgebraicHasher<F>,
    {
        let previous_proof_elements = self.parse_public_inputs(&ivc_prev_proof.public_inputs);

        // Set the initial elements to be public inputs
        self.register_public_inputs(&previous_proof_elements.initial_block_hash.0);
        self.register_public_input(previous_proof_elements.initial_block_num);
        self.register_public_inputs(&previous_proof_elements.initial_data_root_accumulator.0);

        // For the base case, the previous block is the initial block
        let previous_block_hash = self.random_access_avail_hash(
            ivc_base_case.target,
            vec![
                previous_proof_elements.initial_block_hash,
                previous_proof_elements.latest_block_hash,
            ],
        );

        let previous_block_num = self.random_access(
            ivc_base_case.target,
            vec![
                previous_proof_elements.initial_block_num,
                previous_proof_elements.latest_block_num,
            ],
        );

        let previous_data_root_accumulator = self.random_access_avail_hash(
            ivc_base_case.target,
            vec![
                previous_proof_elements.initial_data_root_accumulator,
                previous_proof_elements.latest_data_root_accumulator,
            ],
        );

        // Verify the header proof
        let (block_hash, block_num, parent_hash, _, data_root) = self.recursive_verify_header::<C>(
            is_small_header,
            small_header_proof,
            large_header_proof,
        );

        // Verify that this header's block number is one greater than the previous header's block number
        let one = self.one();
        let expected_block_num = self.add(previous_block_num, one);
        self.connect(expected_block_num, block_num);

        // Verify that the parent hash is equal to the decoded parent hash
        self.connect_avail_hash(previous_block_hash, parent_hash);

        // Calculate the hash of the extracted fields and add them into the accumulator
        let data_root_acc_hasher = blake2b::<F, D, CHUNK_128_BYTES, HASH_SIZE>(self);

        let mut hasher_idx = 0;
        // Input the accumulator
        for hash_byte in previous_data_root_accumulator.0.iter() {
            let mut bits = self.split_le(*hash_byte, 8);

            bits.reverse();
            assert!(bits.len() == 8);
            for bit in bits.iter() {
                self.connect(data_root_acc_hasher.message[hasher_idx].target, bit.target);
                hasher_idx += 1;
            }
        }

        // Input the data root
        for byte in data_root.0.iter() {
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

        // Register the current header's fields as public inputs
        self.register_public_inputs(&block_hash.0);
        self.register_public_input(block_num);

        for byte_chunk in data_root_acc_hasher.digest.chunks(8) {
            let byte = self.le_sum(byte_chunk.to_vec().iter().rev());
            self.register_public_input(byte);
        }

        let ivc_verifier_data = self.add_verifier_data_public_inputs();

        // verify the previous proof
        self.conditionally_verify_cyclic_proof_or_dummy::<C>(
            ivc_base_case,
            ivc_prev_proof,
            &verify_header_ivc_cd(),
        )
        .expect("generation of cyclic proof circuit failed");

        ivc_verifier_data
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
        header::{
            create_header_circuit, process_large_header_cd, process_large_header_vd,
            process_small_header_cd, process_small_header_vd,
        },
        subchain_verification::{
            create_header_ivc_circuit, parse_public_inputs, verify_header_ivc_vd,
        },
        testing_utils::tests::{BLOCK_HASHES, ENCODED_HEADERS, HEAD_BLOCK_NUM},
        utils::{WitnessEncodedHeader, MAX_LARGE_HEADER_SIZE, MAX_SMALL_HEADER_SIZE},
    };
    use anyhow::Result;
    use log::Level;
    use plonky2::field::types::Field;
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
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
        let (small_header_encoded_header_target, process_small_header_data, dummy_small_proof) =
            create_header_circuit::<C, F, D, MAX_SMALL_HEADER_SIZE>();
        assert!(process_small_header_data.common == process_small_header_cd());
        assert!(process_small_header_data.verifier_only == process_small_header_vd());

        let (large_header_encoded_header_target, process_large_header_data, dummy_large_proof) =
            create_header_circuit::<C, F, D, MAX_LARGE_HEADER_SIZE>();
        assert!(process_large_header_data.common == process_large_header_cd());
        assert!(process_large_header_data.verifier_only == process_large_header_vd());

        let (header_ivc_targets, header_ivc_data) = create_header_ivc_circuit();

        let initial_block_hash_val = hex::decode(BLOCK_HASHES[0]).unwrap();
        let initial_block_num_val = HEAD_BLOCK_NUM;
        let initial_data_root_accumulator_val = [1u8; 32];

        let mut use_prev_proof = false;
        let mut prev_proof: Option<ProofWithPublicInputs<F, C, D>> = None;
        let mut header_num = initial_block_num_val + 1;

        // The first encoded header is the HEAD header.  We assume that is already verified.
        for header in ENCODED_HEADERS[1..].iter() {
            // First generate the individual header proof
            let mut header_pw = PartialWitness::new();
            let header_bytes = hex::decode(header).expect("Expect a valid hex string");
            let is_small_header = header_bytes.len() <= MAX_SMALL_HEADER_SIZE;

            println!(
                "Generating proof for header: {}, is_small_header: {}",
                header_num, is_small_header
            );

            let mut small_header_proof = dummy_small_proof.clone();
            let mut large_header_proof = dummy_large_proof.clone();
            if is_small_header {
                header_pw.set_encoded_header_target(
                    &small_header_encoded_header_target,
                    header_bytes.clone(),
                );
                let mut small_header_timing =
                    TimingTree::new("small header proof gen", Level::Info);
                small_header_proof = prove::<F, C, D>(
                    &process_small_header_data.prover_only,
                    &process_small_header_data.common,
                    header_pw,
                    &mut small_header_timing,
                )?;
                small_header_timing.print();
                process_small_header_data.verify(small_header_proof.clone())?;
            } else {
                header_pw.set_encoded_header_target(
                    &large_header_encoded_header_target,
                    header_bytes.clone(),
                );
                let mut large_header_timing =
                    TimingTree::new("large header proof gen", Level::Info);
                large_header_proof = prove::<F, C, D>(
                    &process_large_header_data.prover_only,
                    &process_large_header_data.common,
                    header_pw,
                    &mut large_header_timing,
                )?;
                large_header_timing.print();
                process_large_header_data.verify(large_header_proof.clone())?;
            }

            let mut header_ivc_pw = PartialWitness::new();
            header_ivc_pw.set_bool_target(header_ivc_targets.ivc_base_case, use_prev_proof);

            header_ivc_pw.set_bool_target(header_ivc_targets.is_small_header, is_small_header);

            header_ivc_pw.set_proof_with_pis_target(
                &header_ivc_targets.small_header_proof,
                &small_header_proof,
            );

            header_ivc_pw.set_proof_with_pis_target(
                &header_ivc_targets.large_header_proof,
                &large_header_proof,
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
                    &header_ivc_data.common,
                    &header_ivc_data.verifier_only,
                    initial_pi_map,
                );

                header_ivc_pw.set_proof_with_pis_target::<C, D>(
                    &header_ivc_targets.ivc_prev_proof,
                    &base_proof,
                );
            } else {
                header_ivc_pw.set_proof_with_pis_target::<C, D>(
                    &header_ivc_targets.ivc_prev_proof,
                    &prev_proof.expect("some be a Some value"),
                );
            }

            header_ivc_pw.set_verifier_data_target(
                &header_ivc_targets.verifier_circuit_target,
                &verify_header_ivc_vd::<C, F, D>(),
            );

            let mut ivc_timing = TimingTree::new("ivc proof gen", Level::Info);
            let proof = prove::<F, C, D>(
                &header_ivc_data.prover_only,
                &header_ivc_data.common,
                header_ivc_pw,
                &mut ivc_timing,
            )?;
            ivc_timing.print();

            check_cyclic_proof_verifier_data(
                &proof,
                &header_ivc_data.verifier_only,
                &header_ivc_data.common,
            )?;

            header_ivc_data.verify(proof.clone())?;
            println!("proof for block {} is valid", header_num);

            prev_proof = Some(proof);
            use_prev_proof = true;
            header_num += 1;
        }

        let final_proof = prev_proof.expect("prev_proof must be a Some value");

        // Verify all of the final proof's public inputs are expected.
        let proof_pis = parse_public_inputs::<C, F, D>(final_proof.clone().public_inputs);

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
                == hex::decode("feca63bd2df984e9b737f8b58e914cbe6bb0c8dac7fb1b5c5a13c8a9ca952718")
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
