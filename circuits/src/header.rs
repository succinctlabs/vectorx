use curta::math::goldilocks::cubic::GoldilocksCubicParameters;
use hashbrown::HashMap;

use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    gates::{constant::ConstantGate, gate::Gate},
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        config::{AlgebraicHasher, GenericConfig},
        proof::ProofWithPublicInputs,
    },
    recursion::dummy_circuit::cyclic_base_proof,
};
use plonky2x::backend::circuit::GateRegistry;
use plonky2x::frontend::hash::blake2::blake2b::blake2b;
use plonky2x::prelude::PlonkParameters;
use std::fs::File;
use std::io::prelude::*;

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
    // TODO: should this `gate` be added into the `process_header` function?
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

struct MyParams<F, const D: usize>;
impl<F, D> PlonkParameters<D> for MyParams<F, D> {
    type Field = F;
    type Config = GoldilocksCubicParameters;
    type 
}

pub(crate) fn process_small_header_cd<F: RichField + Extendable<D>, const D: usize>(
) -> CommonCircuitData<F, D> {
    let mut file = File::open("circuit_data/header_small_common.bin").unwrap();
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes).unwrap();

    let res = CommonCircuitData::<F, D>::from_bytes(bytes, &GateRegistry::<L, D>::new());
    return res.unwrap();
}

pub(crate) fn process_small_header_vd<
    C: GenericConfig<D, F = F> + 'static,
    F: RichField + Extendable<D>,
    const D: usize,
>() -> VerifierOnlyCircuitData<C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let mut file = File::open("circuit_data/header_small_verifier.bin").unwrap();
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes).unwrap();
    let res = VerifierOnlyCircuitData::<C, D>::from_bytes(bytes);
    return res.unwrap();
}

pub(crate) fn process_large_header_cd<F: RichField + Extendable<D>, const D: usize>(
) -> CommonCircuitData<F, D> {
    let mut file = File::open("circuit_data/header_large_common.bin").unwrap();
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes).unwrap();
    let res = CommonCircuitData::<F, D>::from_bytes(bytes, &GateRegistry::new());
    return res.unwrap();
}

pub(crate) fn process_large_header_vd<
    C: GenericConfig<D, F = F> + 'static,
    F: RichField + Extendable<D>,
    const D: usize,
>() -> VerifierOnlyCircuitData<C, D>
where
    C::Hasher: AlgebraicHasher<F>,
{
    let mut file = File::open("circuit_data/header_large_verifier.bin").unwrap();
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes).unwrap();
    let res = VerifierOnlyCircuitData::<C, D>::from_bytes(bytes);
    return res.unwrap();
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
    use super::*;
    use crate::utils::MAX_SMALL_HEADER_SIZE;
    use crate::{
        header::{parse_header_pi, CircuitBuilderHeader},
        testing_utils::tests::{
            BLOCK_HASHES, DATA_ROOTS, ENCODED_HEADERS, HEAD_BLOCK_NUM, NUM_BLOCKS, PARENT_HASHES,
            STATE_ROOTS,
        },
        utils::{EncodedHeaderTarget, MAX_LARGE_HEADER_SIZE},
    };
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

    // TODO: skip this test in CI since it takes a long time to build the circuit
    #[test]
    fn test_header_circuit_data_serialization() -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let mut builder_logger = env_logger::Builder::from_default_env();
        builder_logger.format_timestamp(None);
        builder_logger.filter_level(log::LevelFilter::Trace);
        builder_logger.try_init()?;

        const MAX_MICRO_HEADER_SIZE: usize = 128usize;

        let sizes = [
            ("micro", MAX_MICRO_HEADER_SIZE),
            ("small", MAX_SMALL_HEADER_SIZE),
            ("large", MAX_LARGE_HEADER_SIZE),
        ];

        for (name, size) in sizes {
            println!("Serializing header with size: {}", name);
            let config = CircuitConfig::standard_recursion_config();
            let mut builder = CircuitBuilder::<F, D>::new(config);

            let mut header_bytes = Vec::new();
            for _i in 0..size {
                header_bytes.push(builder.add_virtual_target());
            }

            let header_size = builder.add_virtual_target();

            // We have to do this because `EncodedHeaderTarget` requires a const generic and `size` is not a const
            match name {
                "micro" => {
                    builder.process_header(&EncodedHeaderTarget::<MAX_MICRO_HEADER_SIZE> {
                        header_bytes: header_bytes.as_slice().try_into().unwrap(),
                        header_size,
                    });
                }
                "small" => {
                    builder.process_header(&EncodedHeaderTarget::<MAX_SMALL_HEADER_SIZE> {
                        header_bytes: header_bytes.as_slice().try_into().unwrap(),
                        header_size,
                    });
                }
                "large" => {
                    builder.process_header(&EncodedHeaderTarget::<MAX_LARGE_HEADER_SIZE> {
                        header_bytes: header_bytes.as_slice().try_into().unwrap(),
                        header_size,
                    });
                }
                _ => unreachable!(),
            }

            builder.add_gate(ConstantGate::new(2), Vec::new());
            let data = builder.build::<C>();
            let serialized_common_data = data.common.to_bytes(&GateRegistry::new()).unwrap();
            let serialized_verifier_data = data.verifier_only.to_bytes().unwrap();
            let common_filename = format!("circuit_data/header_{}_common.bin", name);
            let verifier_filename = format!("circuit_data/header_{}_verifier.bin", name);
            let mut file = File::create(common_filename)?;
            file.write_all(&serialized_common_data)?;
            let mut file = File::create(verifier_filename)?;
            file.write_all(&serialized_verifier_data)?;

            // Now do the checks that the deserialized version == serialized version
            match name {
                "small" => {
                    let deserialized_common_data = process_small_header_cd::<F, D>();
                    let deserialized_verifier_data = process_small_header_vd::<C, F, D>();
                    assert_eq!(data.common, deserialized_common_data);
                    assert_eq!(data.verifier_only, deserialized_verifier_data);
                }
                "large" => {
                    let deserialized_common_data = process_large_header_cd::<F, D>();
                    let deserialized_verifier_data = process_large_header_vd::<C, F, D>();
                    assert_eq!(data.common, deserialized_common_data);
                    assert_eq!(data.verifier_only, deserialized_verifier_data);
                }
                "micro" => {}
                _ => unreachable!(),
            }
        }
        Ok(())
    }

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
