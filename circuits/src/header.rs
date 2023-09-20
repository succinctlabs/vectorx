use hashbrown::HashMap;
use itertools::Itertools;
use plonky2::field::extension::Extendable;
use plonky2::fri::reduction_strategies::FriReductionStrategy;
use plonky2::fri::{FriConfig, FriParams};
use plonky2::gates::arithmetic_base::ArithmeticGate;
use plonky2::gates::base_sum::BaseSumGate;
use plonky2::gates::constant::ConstantGate;
use plonky2::gates::gate::GateRef;
use plonky2::gates::noop::NoopGate;
use plonky2::gates::poseidon::PoseidonGate;
use plonky2::gates::public_input::PublicInputGate;
use plonky2::gates::random_access::RandomAccessGate;
use plonky2::gates::selectors::SelectorsInfo;
use plonky2::hash::hash_types::{HashOut, RichField};
use plonky2::hash::merkle_tree::MerkleCap;
use plonky2::iop::target::Target;
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2::plonk::proof::ProofWithPublicInputs;
use plonky2::recursion::dummy_circuit::cyclic_base_proof;
use plonky2x::frontend::hash::blake2::blake2b::blake2b;
use plonky2x::frontend::num::u32::gates::add_many_u32::U32AddManyGate;

use crate::decoder::CircuitBuilderHeaderDecoder;
use crate::utils::{AvailHashTarget, EncodedHeaderTarget, HASH_SIZE};

pub(crate) fn create_header_circuit<
    C: GenericConfig<D, F = F> + 'static,
    F: RichField + Extendable<D>,
    const D: usize,
    const S: usize,
>() -> (
    EncodedHeaderTarget<S>,
    CircuitData<F, C, D>,
    ProofWithPublicInputs<F, C, D>,
)
where
    C::Hasher: AlgebraicHasher<F>,
{
    let config = CircuitConfig::standard_recursion_config();
    let mut process_header_builder = CircuitBuilder::<F, D>::new(config);

    let mut header_bytes = Vec::new();
    for _i in 0..S {
        header_bytes.push(process_header_builder.add_virtual_target());
    }

    let header_size = process_header_builder.add_virtual_target();

    let encoded_header_target = EncodedHeaderTarget::<S> {
        header_bytes: header_bytes.as_slice().try_into().unwrap(),
        header_size,
    };

    process_header_builder.process_header(&encoded_header_target);

    process_header_builder.add_gate(ConstantGate::new(2), Vec::new());

    let process_header_data = process_header_builder.build::<C>();

    let dummy_proof = cyclic_base_proof::<F, C, D>(
        &process_header_data.common,
        &process_header_data.verifier_only,
        HashMap::<usize, F>::new(),
    );

    // TODO: Return dummy_proof as a reference type
    (encoded_header_target, process_header_data, dummy_proof)
}

#[derive(Debug)]
pub struct HeaderPIElements {
    pub block_hash: [u8; HASH_SIZE],
    pub block_num: u32,
    pub parent_hash: [u8; HASH_SIZE],
    pub state_root: [u8; HASH_SIZE],
    pub data_root: [u8; HASH_SIZE],
}

fn parse_header_pi<
    C: GenericConfig<D, F = F> + 'static,
    F: RichField + Extendable<D>,
    const D: usize,
>(
    public_inputs: Vec<F>,
) -> HeaderPIElements
where
    C::Hasher: AlgebraicHasher<F>,
{
    let cd = process_small_header_cd::<F, D>();
    let public_inputs_len = cd.num_public_inputs;
    assert!(public_inputs.len() == public_inputs_len);

    let canonical_public_inputs = public_inputs
        .iter()
        .take(public_inputs_len)
        .map(|x| {
            u32::try_from(F::to_canonical_u64(x)).expect("element in public inputs is not a u32")
        })
        .collect_vec();
    let mut public_inputs_iter = canonical_public_inputs.iter();

    // I feel like there should have been a utility function instead of the long-ish amounts of code
    // below
    HeaderPIElements {
        block_hash:
                public_inputs_iter
                .by_ref()
                .take(HASH_SIZE)
                .map(|x| u8::try_from(*x).expect("element in public inputs is not a u8"))
                .collect_vec()
                .as_slice()
                .try_into()
                .expect("can't take HASH_SIZE elements from public inputs for initial block hash"),
        block_num: *public_inputs_iter.by_ref().take(1).collect_vec()[0],
        parent_hash: public_inputs_iter
                .by_ref()
                .take(HASH_SIZE)
                .map(|x| u8::try_from(*x).expect("element in public inputs is not a u8"))
                .collect_vec()
                .as_slice()
                .try_into()
                .expect("can't take HASH_SIZE elements from public inputs for initial data root accumulator"),
        state_root: public_inputs_iter
                .by_ref().
                take(HASH_SIZE)
                .map(|x| u8::try_from(*x).expect("element in public inputs is not a u8"))
                .collect_vec()
                .as_slice()
                .try_into()
                .expect("can't take HASH_SIZE elements from public inputs for latest block hash"),
        data_root: public_inputs_iter
                .by_ref()
                .take(HASH_SIZE)
                .map(|x| u8::try_from(*x).expect("element in public inputs is not a u8"))
                .collect_vec()
                .as_slice()
                .try_into()
                .expect("can't take HASH_SIZE elements from public inputs for latest data root accumulator"),
    }
}

// Of course in the future, we really shouldn't have stuff like this in the code.
// Even if it's a short-cut in the short-term, in the long-term actually we waste more time because it's a lot
// less reproducible and when the circuit changes copy-pasting the values into the code takes a non-trivial amount of time
// Better to just fix even in the short-term
pub(crate) fn process_small_header_cd<F: RichField + Extendable<D>, const D: usize>(
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
            degree_bits: 17,
            reduction_arity_bits: vec![4, 4, 4],
        },

        gates: vec![
            GateRef::new(NoopGate {}),
            GateRef::new(ConstantGate { num_consts: 2 }),
            GateRef::new(PublicInputGate {}),
            GateRef::new(BaseSumGate::<2>::new(32)),
            GateRef::new(BaseSumGate::<2>::new(63)),
            GateRef::new(ArithmeticGate { num_ops: 20 }),
            GateRef::new(RandomAccessGate {
                bits: 2,
                num_copies: 13,
                num_extra_constants: 2,
                _phantom: std::marker::PhantomData,
            }),
            GateRef::new(U32AddManyGate {
                num_addends: 3,
                num_ops: 5,
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
            selector_indices: vec![0, 0, 0, 0, 0, 0, 1, 1, 1, 2],
            groups: vec![0..6, 6..9, 9..10],
        },
        quotient_degree_factor: 8,
        num_gate_constraints: 123,
        num_constants: 5,
        num_public_inputs: 129,
        k_is: k_i_fields,
        num_partial_products: 9,
        num_lookup_polys: 0,
        num_lookup_selectors: 0,
        luts: vec![],
    }
}

pub(crate) fn process_small_header_vd<
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
                    F::from_canonical_u64(2225237877069907407),
                    F::from_canonical_u64(10674148293308845336),
                    F::from_canonical_u64(14823520364480047584),
                    F::from_canonical_u64(13041944328210437542),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(18130325122772056688),
                    F::from_canonical_u64(10297034932705946583),
                    F::from_canonical_u64(7831131987745788328),
                    F::from_canonical_u64(5433367898224201257),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(9738602811857454652),
                    F::from_canonical_u64(11915363904116586060),
                    F::from_canonical_u64(6099863057817048289),
                    F::from_canonical_u64(4493606437809735588),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(12883310535079161837),
                    F::from_canonical_u64(10618991311810071630),
                    F::from_canonical_u64(2137473946644807275),
                    F::from_canonical_u64(3726556069812201864),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(177697818080834357),
                    F::from_canonical_u64(6652567672576424474),
                    F::from_canonical_u64(6494613222534332869),
                    F::from_canonical_u64(301143041642317549),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(8013085152330762386),
                    F::from_canonical_u64(7648899628547953161),
                    F::from_canonical_u64(4893911320366126652),
                    F::from_canonical_u64(6974030436586719837),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(2616622367600487982),
                    F::from_canonical_u64(12564975857666574394),
                    F::from_canonical_u64(13069634195342495102),
                    F::from_canonical_u64(6665617880637771057),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(12061485440385284766),
                    F::from_canonical_u64(13378781476401091706),
                    F::from_canonical_u64(2420318842101159779),
                    F::from_canonical_u64(11391172263349925942),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(15874928324721359140),
                    F::from_canonical_u64(13032855244244535357),
                    F::from_canonical_u64(8488223230767028880),
                    F::from_canonical_u64(15511313247887978135),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(12845646395689872757),
                    F::from_canonical_u64(9870847263694311800),
                    F::from_canonical_u64(14722705793325867125),
                    F::from_canonical_u64(8089006096019652991),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(609811383094099811),
                    F::from_canonical_u64(17323219303386865394),
                    F::from_canonical_u64(7068726368880957562),
                    F::from_canonical_u64(15440481346744611180),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(15628875462818780756),
                    F::from_canonical_u64(1669344533290409107),
                    F::from_canonical_u64(13965878162152564127),
                    F::from_canonical_u64(10764686370266574853),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(7481612714048488488),
                    F::from_canonical_u64(8993085354947915990),
                    F::from_canonical_u64(11936995863388761142),
                    F::from_canonical_u64(14612448567197222172),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(15727726741168328527),
                    F::from_canonical_u64(10760001756989711346),
                    F::from_canonical_u64(10578654710127104478),
                    F::from_canonical_u64(16726302363698099222),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(2303016756715619913),
                    F::from_canonical_u64(16742196886787181724),
                    F::from_canonical_u64(999047734543514106),
                    F::from_canonical_u64(4464180999797409736),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(6349785910978155683),
                    F::from_canonical_u64(10755169522529422692),
                    F::from_canonical_u64(10700931298708442328),
                    F::from_canonical_u64(2457890654590200256),
                ],
            },
        ]),

        circuit_digest: HashOut {
            elements: [
                F::from_canonical_u64(16543068341236581582),
                F::from_canonical_u64(13290864990913383358),
                F::from_canonical_u64(1626855543267329516),
                F::from_canonical_u64(15071333207764330239),
            ],
        },
    }
}

pub(crate) fn process_large_header_cd<F: RichField + Extendable<D>, const D: usize>(
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
            degree_bits: 19,
            reduction_arity_bits: vec![4, 4, 4, 4],
        },

        gates: vec![
            GateRef::new(NoopGate {}),
            GateRef::new(ConstantGate { num_consts: 2 }),
            GateRef::new(PublicInputGate {}),
            GateRef::new(BaseSumGate::<2>::new(32)),
            GateRef::new(BaseSumGate::<2>::new(63)),
            GateRef::new(ArithmeticGate { num_ops: 20 }),
            GateRef::new(RandomAccessGate {
                bits: 2,
                num_copies: 13,
                num_extra_constants: 2,
                _phantom: std::marker::PhantomData,
            }),
            GateRef::new(U32AddManyGate {
                num_addends: 3,
                num_ops: 5,
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
            selector_indices: vec![0, 0, 0, 0, 0, 0, 1, 1, 1, 2],
            groups: vec![0..6, 6..9, 9..10],
        },
        quotient_degree_factor: 8,
        num_gate_constraints: 123,
        num_constants: 5,
        num_public_inputs: 129,
        k_is: k_i_fields,
        num_partial_products: 9,
        num_lookup_polys: 0,
        num_lookup_selectors: 0,
        luts: vec![],
    }
}

pub(crate) fn process_large_header_vd<
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
                    F::from_canonical_u64(14661796354882620617),
                    F::from_canonical_u64(12445062506583636561),
                    F::from_canonical_u64(2309818448300437890),
                    F::from_canonical_u64(8059997968192733063),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(17727999767334204722),
                    F::from_canonical_u64(18115716908813330362),
                    F::from_canonical_u64(10649768514979183632),
                    F::from_canonical_u64(15494126047430098110),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(5301421276083589236),
                    F::from_canonical_u64(12188105848661816489),
                    F::from_canonical_u64(14727217223135707740),
                    F::from_canonical_u64(3553453398074752873),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(15798062677231300933),
                    F::from_canonical_u64(10033491924330427181),
                    F::from_canonical_u64(7441012014916954813),
                    F::from_canonical_u64(6688606264537782107),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(1810000525154411085),
                    F::from_canonical_u64(12402970935917922763),
                    F::from_canonical_u64(15362112929834649564),
                    F::from_canonical_u64(15057877332800617307),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(9850858648768805587),
                    F::from_canonical_u64(1802135345259886188),
                    F::from_canonical_u64(1906395405558122904),
                    F::from_canonical_u64(7246805658530012513),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(6269072496513204232),
                    F::from_canonical_u64(9990047000135906072),
                    F::from_canonical_u64(6649971609635253076),
                    F::from_canonical_u64(171737386510219015),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(2595078383499676997),
                    F::from_canonical_u64(6809009889044672602),
                    F::from_canonical_u64(5400745440235262322),
                    F::from_canonical_u64(15481799715896649956),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(5006035455749893123),
                    F::from_canonical_u64(17152535856791096703),
                    F::from_canonical_u64(16829865367806989433),
                    F::from_canonical_u64(1143895198204273937),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(4473582809915808426),
                    F::from_canonical_u64(3486471219046889438),
                    F::from_canonical_u64(18269699385591255747),
                    F::from_canonical_u64(3464634817742627425),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(9278685920993126229),
                    F::from_canonical_u64(639041725189615739),
                    F::from_canonical_u64(3953600378196575628),
                    F::from_canonical_u64(7019856200862742323),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(7590307919683133237),
                    F::from_canonical_u64(14942737493850707882),
                    F::from_canonical_u64(15340172284853970150),
                    F::from_canonical_u64(9630829890419662772),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(15307467502834365803),
                    F::from_canonical_u64(12679866560206714589),
                    F::from_canonical_u64(3432285442637758223),
                    F::from_canonical_u64(3932981594259069122),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(6597905450374772126),
                    F::from_canonical_u64(15251469694413996654),
                    F::from_canonical_u64(5507012072752181856),
                    F::from_canonical_u64(3161268596544157086),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(18254395526960786209),
                    F::from_canonical_u64(7756845751261062747),
                    F::from_canonical_u64(11221092307283610329),
                    F::from_canonical_u64(652300524684955646),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(12434401119237801195),
                    F::from_canonical_u64(15519798846113569664),
                    F::from_canonical_u64(423402063834367275),
                    F::from_canonical_u64(4101774627721266630),
                ],
            },
        ]),
        circuit_digest: HashOut {
            elements: [
                F::from_canonical_u64(5987405960598249402),
                F::from_canonical_u64(12794870433248054655),
                F::from_canonical_u64(15987930887553177889),
                F::from_canonical_u64(12375253152617882572),
            ],
        },
    }
}
pub struct VerifyHeaderPIs {
    pub block_hash: AvailHashTarget,
    pub block_num: Target,
    pub parent_hash: AvailHashTarget,
    pub state_root: AvailHashTarget,
    pub data_root: AvailHashTarget,
}

pub trait CircuitBuilderHeader<F: RichField + Extendable<D>, const D: usize> {
    fn process_header<const S: usize>(&mut self, encoded_header: &EncodedHeaderTarget<S>);

    fn parse_header_pi(&mut self, public_inputs: &[Target]) -> VerifyHeaderPIs;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderHeader<F, D>
    for CircuitBuilder<F, D>
{
    fn process_header<const S: usize>(&mut self, encoded_header: &EncodedHeaderTarget<S>) {
        // Calculate the hash for the current header
        let header_hasher = blake2b::<F, D, S, HASH_SIZE>(self);

        // Input the encoded header bytes into the hasher
        for i in 0..S {
            // Need to split the bytes into bits
            let mut bits = self.split_le(encoded_header.header_bytes[i], 8);

            // Needs to be in bit big endian order for the EDDSA verification circuit
            bits.reverse();
            for (j, bit) in bits.iter().enumerate().take(8) {
                self.connect(header_hasher.message[i * 8 + j].target, bit.target);
            }
        }

        self.connect(header_hasher.message_len, encoded_header.header_size);

        // Convert the digest (vector of bits) to bytes
        let mut header_hash_bytes = Vec::new();
        for byte_chunk in header_hasher.digest.chunks(8) {
            let byte = self.le_sum(byte_chunk.to_vec().iter().rev());
            self.register_public_input(byte);
            header_hash_bytes.push(byte);
        }

        // Get the decoded_header object to retrieve the block numbers and parent hashes
        let decoded_header = self.decode_header::<S>(
            encoded_header,
            AvailHashTarget(header_hash_bytes.as_slice().try_into().unwrap()),
        );

        // NOTE: I don't think it's great to do the public input registration here
        // It mixes constraint logic with the public input registration logic
        self.register_public_input(decoded_header.block_number);
        self.register_public_inputs(decoded_header.parent_hash.0.as_slice());
        self.register_public_inputs(decoded_header.state_root.0.as_slice());
        self.register_public_inputs(decoded_header.data_root.0.as_slice());
    }

    fn parse_header_pi(&mut self, public_inputs: &[Target]) -> VerifyHeaderPIs {
        let mut public_inputs_iter = public_inputs.iter();

        VerifyHeaderPIs {
            block_hash: AvailHashTarget(
                public_inputs_iter
                    .by_ref()
                    .take(HASH_SIZE)
                    .copied()
                    .collect_vec()
                    .as_slice()
                    .try_into()
                    .unwrap(),
            ),
            block_num: *public_inputs_iter.by_ref().take(1).collect_vec()[0],
            parent_hash: AvailHashTarget(
                public_inputs_iter
                    .by_ref()
                    .take(HASH_SIZE)
                    .copied()
                    .collect_vec()
                    .as_slice()
                    .try_into()
                    .unwrap(),
            ),
            state_root: AvailHashTarget(
                public_inputs_iter
                    .by_ref()
                    .take(HASH_SIZE)
                    .copied()
                    .collect_vec()
                    .as_slice()
                    .try_into()
                    .unwrap(),
            ),
            data_root: AvailHashTarget(
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
mod tests {
    use anyhow::{Ok, Result};
    use plonky2::field::types::Field;
    use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};

    use crate::header::{parse_header_pi, CircuitBuilderHeader};
    use crate::testing_utils::tests::{
        BLOCK_HASHES, DATA_ROOTS, ENCODED_HEADERS, HEAD_BLOCK_NUM, NUM_BLOCKS, PARENT_HASHES,
        STATE_ROOTS,
    };
    use crate::utils::{EncodedHeaderTarget, MAX_LARGE_HEADER_SIZE};

    #[test]
    fn test_process_block() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        const S: usize = MAX_LARGE_HEADER_SIZE;

        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut header_bytes = Vec::new();
        for _i in 0..S {
            header_bytes.push(builder.add_virtual_target());
        }

        let header_size = builder.add_virtual_target();

        builder.process_header(&EncodedHeaderTarget::<S> {
            header_bytes: header_bytes.as_slice().try_into().unwrap(),
            header_size,
        });

        let data = builder.build::<C>();

        for i in 0..NUM_BLOCKS {
            let block_num = HEAD_BLOCK_NUM + i as u32;
            println!("processing block {}", block_num);

            let mut pw = PartialWitness::new();

            let encoded_header_bytes = hex::decode(ENCODED_HEADERS[i]).unwrap();
            for j in 0..encoded_header_bytes.len() {
                pw.set_target(
                    header_bytes[j],
                    F::from_canonical_u8(encoded_header_bytes[j]),
                );
            }

            // pad the rest of the header bytes with 0s
            for j in encoded_header_bytes.len()..S {
                pw.set_target(header_bytes[j], F::ZERO);
            }

            pw.set_target(
                header_size,
                F::from_canonical_usize(encoded_header_bytes.len()),
            );

            let proof = data.prove(pw)?;
            let _ = data.verify(proof.clone());

            // Verify the public inputs in the proof match the expected values
            let header_fields = parse_header_pi::<C, F, D>(proof.public_inputs);

            assert_eq!(header_fields.block_num, block_num);
            assert_eq!(
                header_fields.block_hash.as_slice(),
                hex::decode(BLOCK_HASHES[i]).unwrap()
            );
            assert_eq!(
                header_fields.state_root.as_slice(),
                hex::decode(STATE_ROOTS[i]).unwrap()
            );
            assert_eq!(
                header_fields.data_root.as_slice(),
                hex::decode(DATA_ROOTS[i]).unwrap()
            );
            assert_eq!(
                header_fields.parent_hash.as_slice(),
                hex::decode(PARENT_HASHES[i]).unwrap()
            );
        }

        Ok(())
    }
}
