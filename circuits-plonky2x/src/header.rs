use std::marker::PhantomData;

use plonky2::plonk::circuit_builder::CircuitBuilder as BaseCircuitBuilder;
use plonky2x::backend::circuit::Circuit;
use plonky2x::prelude::{
    ArrayVariable, Bytes32Variable, CircuitBuilder, CircuitVariable, Field, GoldilocksField,
    PlonkParameters, RichField, Target, Variable, Witness, WitnessWrite,
};

use crate::decoder::DecodingMethods;
use crate::vars::*;

pub trait HeaderMethods {
    fn hash_encoded_header<const S: usize>(
        &mut self,
        header: &EncodedHeaderVariable<S>,
    ) -> Bytes32Variable;

    fn hash_encoded_headers<const S: usize, const N: usize>(
        &mut self,
        headers: &ArrayVariable<EncodedHeaderVariable<S>, N>,
    ) -> ArrayVariable<Bytes32Variable, N>;
}

// This assumes that all the inputted byte array are already range checked (e.g. all bytes are less than 256)
impl<L: PlonkParameters<D>, const D: usize> HeaderMethods for CircuitBuilder<L, D> {
    fn hash_encoded_header<const S: usize>(
        &mut self,
        header: &EncodedHeaderVariable<S>,
    ) -> Bytes32Variable {
        // TODO: given a header bytes that are encoded, blake2b hash the header
        // TODO: this is a placeholder for now
        todo!();
    }

    fn hash_encoded_headers<const S: usize, const N: usize>(
        &mut self,
        headers: &ArrayVariable<EncodedHeaderVariable<S>, N>,
    ) -> ArrayVariable<Bytes32Variable, N> {
        headers
            .as_vec()
            .iter()
            .map(|x| self.hash_encoded_header(x))
            .collect::<Vec<Bytes32Variable>>()
            .try_into()
            .unwrap()
    }
}

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
