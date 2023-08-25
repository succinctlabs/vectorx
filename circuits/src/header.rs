use itertools::Itertools;
use plonky2::{
    field::extension::Extendable,
    hash::hash_types::RichField,
    iop::target::Target,
    plonk::{
        circuit_builder::CircuitBuilder,
        config::{AlgebraicHasher, GenericConfig},
    },
};
use plonky2x::hash::blake2::blake2b::blake2b;

use crate::{
    decoder::CircuitBuilderHeaderDecoder,
    utils::{AvailHashTarget, EncodedHeaderTarget, HASH_SIZE},
};

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
    /*
    let vd = header_vd::<C, F, D>();

    // 4 hashes and 1 block number and the circuit digest and sigma contants cap
    let public_inputs_len = 4 * HASH_SIZE + 1;

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
    */

    let public_inputs_len = 4 * HASH_SIZE + 1;

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
