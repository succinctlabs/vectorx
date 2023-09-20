use plonky2x::backend::circuit::Circuit;
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, GoldilocksField,
    PlonkParameters, RichField, Target, Variable, Witness, WitnessWrite,
};

use crate::decoder::DecodingMethods;
use crate::vars::*;

#[derive(Clone, Debug, CircuitVariable)]
pub struct VerifyHeaderPIs {
    pub block_hash: HashVariable,
    pub block_num: Variable,
    pub parent_hash: HashVariable,
    pub state_root: HashVariable,
    pub data_root: HashVariable,
}

// struct HeaderCircuit<const HEADER_SIZE: usize, const NUM_HEADERS> {}

// impl<const HEADER_SIZE: usize> Circuit for HeaderCircuit<HEADER_SIZE> {
//     fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>) {
//         let header_bytes = builder.read::<ArrayVariable<U8Variable, HEADER_SIZE>>();
//         let header_length = builder.read::<Variable>();
//         let encoded_header = EncodedHeaderVariable {
//             header_bytes,
//             header_size: header_length,
//         };
//         // TODO: get the blake2b header hash instead of builder.init::<> below
//         let header_hash_bytes32 = builder.init::<Bytes32Variable>();
//         let header_hash = builder.to_hash_variable(header_hash_bytes32);
//         let decoded_header = builder.decode_header::<HEADER_SIZE>(encoded_header, header_hash);
//     }
// }

#[cfg(test)]
mod tests {

    use curta::math::prelude::Field;
    // use anyhow::{Ok, Result};
    // use plonky2::field::types::Field;
    // use plonky2::iop::witness::{PartialWitness, WitnessWrite};
    // use plonky2::plonk::circuit_builder::CircuitBuilder;
    // use plonky2::plonk::circuit_data::CircuitConfig;
    // use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2x::prelude::DefaultBuilder;

    use super::*;
    // use crate::header;
    // use crate::testing_utils::tests::{
    //     BLOCK_HASHES, DATA_ROOTS, ENCODED_HEADERS, HEAD_BLOCK_NUM, NUM_BLOCKS, PARENT_HASHES,
    //     STATE_ROOTS,
    // };

    //     #[test]
    //     fn test_process_block() {
    //         const HEADER_SIZE: usize = MAX_LARGE_HEADER_SIZE;

    //         let mut builder_logger = env_logger::Builder::from_default_env();
    //         builder_logger.format_timestamp(None);
    //         builder_logger.filter_level(log::LevelFilter::Trace);
    //         builder_logger.try_init().unwrap();

    //         let mut builder = DefaultBuilder::new();
    //         HeaderCircuit::<HEADER_SIZE>::define(&mut builder);

    //         let circuit = builder.build();

    //         for i in 0..NUM_BLOCKS {
    //             let block_num = HEAD_BLOCK_NUM + i as u32;
    //             println!("processing block {}", block_num);

    //             let mut pw = PartialWitness::new();

    //             let mut encoded_header_bytes = hex::decode(ENCODED_HEADERS[i]).unwrap();
    //             let header_length = encoded_header_bytes.len();
    //             encoded_header_bytes.resize(HEADER_SIZE, 0);

    //             let inputs = circuit.input();
    //             inputs.write::<ArrayVariable<U8Variable, HEADER_SIZE>>(
    //                 encoded_header_bytes.iter().map(|x| *x as u32).collect(), // TODO: change this when we have U8 for real
    //             );
    //             inputs.write::<Variable>(GoldilocksField::from_canonical_usize(header_length));

    //             let proof = data.prove(pw)?;
    //             let _ = data.verify(proof.clone());

    //             // Verify the public inputs in the proof match the expected values
    //             let header_fields = parse_header_pi::<C, F, D>(proof.public_inputs);

    //             assert_eq!(header_fields.block_num, block_num);
    //             assert_eq!(
    //                 header_fields.block_hash.as_slice(),
    //                 hex::decode(BLOCK_HASHES[i]).unwrap()
    //             );
    //             assert_eq!(
    //                 header_fields.state_root.as_slice(),
    //                 hex::decode(STATE_ROOTS[i]).unwrap()
    //             );
    //             assert_eq!(
    //                 header_fields.data_root.as_slice(),
    //                 hex::decode(DATA_ROOTS[i]).unwrap()
    //             );
    //             assert_eq!(
    //                 header_fields.parent_hash.as_slice(),
    //                 hex::decode(PARENT_HASHES[i]).unwrap()
    //             );
    //         }

    //         Ok(())
    //     }
}
