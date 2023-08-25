use hashbrown::HashMap;

use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    fri::{reduction_strategies::FriReductionStrategy, FriConfig, FriParams},
    gates::{
        arithmetic_base::ArithmeticGate, base_sum::BaseSumGate, constant::ConstantGate,
        gate::GateRef, noop::NoopGate, poseidon::PoseidonGate, public_input::PublicInputGate,
        random_access::RandomAccessGate, selectors::SelectorsInfo,
    },
    hash::{
        hash_types::{HashOut, RichField},
        merkle_tree::MerkleCap,
    },
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
    recursion::dummy_circuit::cyclic_base_proof,
};
use plonky2x::{hash::blake2::blake2b::blake2b, num::u32::gates::add_many_u32::U32AddManyGate};

use crate::{
    decoder::CircuitBuilderHeaderDecoder,
    utils::{AvailHashTarget, EncodedHeaderTarget, HASH_SIZE},
};

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

    let process_header_data = process_header_builder.build::<C>();

    let dummy_proof = cyclic_base_proof::<F, C, D>(
        &process_header_data.common,
        &process_header_data.verifier_only,
        HashMap::<usize, F>::new(),
    );

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
                    F::from_canonical_u64(8711776516590847690),
                    F::from_canonical_u64(6689337593265916366),
                    F::from_canonical_u64(8475850867895631531),
                    F::from_canonical_u64(40682170367083097),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(8132744300691276554),
                    F::from_canonical_u64(7033745181140593623),
                    F::from_canonical_u64(13077842940465272446),
                    F::from_canonical_u64(15599450899648253655),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(16453775900251790654),
                    F::from_canonical_u64(16197696523919300452),
                    F::from_canonical_u64(6251405225011934775),
                    F::from_canonical_u64(18232359980231045909),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(1504463206181608874),
                    F::from_canonical_u64(16046278584711003528),
                    F::from_canonical_u64(6430230359719217949),
                    F::from_canonical_u64(6322189192537315287),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(6445651932566296820),
                    F::from_canonical_u64(17703725366866678889),
                    F::from_canonical_u64(13995775945532477794),
                    F::from_canonical_u64(9696897253618194004),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(8123364066376701516),
                    F::from_canonical_u64(18278562286209858720),
                    F::from_canonical_u64(8043870000048164270),
                    F::from_canonical_u64(13159417434636915726),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(3384363148650751962),
                    F::from_canonical_u64(776596387166343445),
                    F::from_canonical_u64(10899997266973042165),
                    F::from_canonical_u64(13946609561928543450),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(10393064240259753619),
                    F::from_canonical_u64(8210797836965271205),
                    F::from_canonical_u64(3074514415068555075),
                    F::from_canonical_u64(17434677342129006807),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(1076908457798007406),
                    F::from_canonical_u64(18085980942810609336),
                    F::from_canonical_u64(14716417055994859554),
                    F::from_canonical_u64(15285608525742490274),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(11305355795159786594),
                    F::from_canonical_u64(10563989663047664457),
                    F::from_canonical_u64(15605218500335408058),
                    F::from_canonical_u64(7352604774252389427),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(8345057542944899170),
                    F::from_canonical_u64(5832931401799754626),
                    F::from_canonical_u64(5204992508845059354),
                    F::from_canonical_u64(893684633686180944),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(15909215196558967994),
                    F::from_canonical_u64(5814589981288843625),
                    F::from_canonical_u64(10561388689924585156),
                    F::from_canonical_u64(2632453557586503482),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(1365314270606219843),
                    F::from_canonical_u64(8856919480624818749),
                    F::from_canonical_u64(13409881616246528546),
                    F::from_canonical_u64(5997592209262528913),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(17593511723426799142),
                    F::from_canonical_u64(6922058928752112047),
                    F::from_canonical_u64(2223120864170750809),
                    F::from_canonical_u64(11041452708798138401),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(18105556238942927787),
                    F::from_canonical_u64(17592963491794876444),
                    F::from_canonical_u64(10202105524208304032),
                    F::from_canonical_u64(6279499652370770965),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(2235770242976949206),
                    F::from_canonical_u64(2276324456813312040),
                    F::from_canonical_u64(15128151491866380512),
                    F::from_canonical_u64(16791665378812967109),
                ],
            },
        ]),
        circuit_digest: HashOut {
            elements: [
                F::from_canonical_u64(5036480820287603163),
                F::from_canonical_u64(8836813599719692297),
                F::from_canonical_u64(9740369935713788688),
                F::from_canonical_u64(17081157849138175389),
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
                    F::from_canonical_u64(2916506838420528258),
                    F::from_canonical_u64(2320934456167974730),
                    F::from_canonical_u64(3080705498343833603),
                    F::from_canonical_u64(17919935677369988721),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(3743919344105588164),
                    F::from_canonical_u64(5362874409438510562),
                    F::from_canonical_u64(9559026330146210697),
                    F::from_canonical_u64(8204292728374690960),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(7656803409610104741),
                    F::from_canonical_u64(9552965662154114951),
                    F::from_canonical_u64(15087539475410227350),
                    F::from_canonical_u64(15271881324122222793),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(11248967163765756871),
                    F::from_canonical_u64(7893680784586735374),
                    F::from_canonical_u64(8709339270421946590),
                    F::from_canonical_u64(12487830521705750437),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(15767620760375553480),
                    F::from_canonical_u64(11972496133714303629),
                    F::from_canonical_u64(7817927340578460619),
                    F::from_canonical_u64(8835663807225447279),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(2539742860236534874),
                    F::from_canonical_u64(1027162961628274349),
                    F::from_canonical_u64(17607312894015084729),
                    F::from_canonical_u64(8233404176617845083),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(14462483373475933319),
                    F::from_canonical_u64(11930481353067841407),
                    F::from_canonical_u64(15391037352906179979),
                    F::from_canonical_u64(6234639378728843941),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(15164679448607890595),
                    F::from_canonical_u64(11500254393842867751),
                    F::from_canonical_u64(18342394242042110877),
                    F::from_canonical_u64(13524070048187672653),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(2609040372020847144),
                    F::from_canonical_u64(5447251298987659918),
                    F::from_canonical_u64(14996630094406026909),
                    F::from_canonical_u64(10674441719597356061),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(15946742519239705635),
                    F::from_canonical_u64(10087614811792732896),
                    F::from_canonical_u64(8411200178077432139),
                    F::from_canonical_u64(9219284605954729278),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(14627614106482101284),
                    F::from_canonical_u64(16599861286184885049),
                    F::from_canonical_u64(7632806206315151451),
                    F::from_canonical_u64(4062893097071907486),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(10467505589862248747),
                    F::from_canonical_u64(7863670263691743468),
                    F::from_canonical_u64(2990655735464746347),
                    F::from_canonical_u64(4808153379266177036),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(1960004200043945152),
                    F::from_canonical_u64(14029854479581292961),
                    F::from_canonical_u64(1632636849053368813),
                    F::from_canonical_u64(9588798835294527857),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(6180083795859083822),
                    F::from_canonical_u64(17363179284662966104),
                    F::from_canonical_u64(5492964616166921857),
                    F::from_canonical_u64(3291666679571504240),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(17477553455529941962),
                    F::from_canonical_u64(7407023775976379582),
                    F::from_canonical_u64(4559214944083897332),
                    F::from_canonical_u64(7754156744169744965),
                ],
            },
            HashOut {
                elements: [
                    F::from_canonical_u64(16713142606743868705),
                    F::from_canonical_u64(17556117177175217316),
                    F::from_canonical_u64(15806488347580783316),
                    F::from_canonical_u64(14317904094363612523),
                ],
            },
        ]),
        circuit_digest: HashOut {
            elements: [
                F::from_canonical_u64(3924152851894677722),
                F::from_canonical_u64(13818047069862419455),
                F::from_canonical_u64(7141065522426245206),
                F::from_canonical_u64(11958697800088054378),
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
    use plonky2::{
        iop::witness::{PartialWitness, WitnessWrite},
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::CircuitConfig,
            config::{GenericConfig, PoseidonGoldilocksConfig},
        },
    };

    use crate::{
        header::{parse_header_pi, CircuitBuilderHeader},
        testing_utils::tests::{
            BLOCK_HASHES, DATA_ROOTS, ENCODED_HEADERS, HEAD_BLOCK_NUM, NUM_BLOCKS, PARENT_HASHES,
            STATE_ROOTS,
        },
        utils::{EncodedHeaderTarget, MAX_LARGE_HEADER_SIZE},
    };

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
