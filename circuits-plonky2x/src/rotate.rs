use async_trait::async_trait;
use avail_subxt::config::substrate::DigestItem;
use avail_subxt::primitives::Header;
use codec::Encode;
use log::{debug, Level};
use plonky2x::backend::circuit::Circuit;
use plonky2x::frontend::hint::asynchronous::hint::AsyncHint;
use plonky2x::frontend::uint::uint64::U64Variable;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{
    Bytes32Variable, CircuitBuilder, Field, PlonkParameters, ValueStream, Variable, VariableStream,
};
use serde::{Deserialize, Serialize};

use crate::builder::decoder::FloorDivGenerator;
use crate::builder::header::HeaderMethods;
use crate::builder::justification::{GrandpaJustificationVerifier, HintSimpleJustification};
use crate::builder::rotate::RotateMethods;
use crate::consts::MAX_HEADER_CHUNK_SIZE;
use crate::input::RpcDataFetcher;
use crate::vars::{EncodedHeader, EncodedHeaderVariable};

async fn parse_single_header_rotate(header: Header) -> (usize, usize, usize) {
    let fetcher = RpcDataFetcher::new().await;

    // let authority_set_id = fetcher.get_authority_set_id(header.number).await;

    let authorities = fetcher.get_authorities(header.number).await;

    let mut position = 0;
    let number_encoded = header.number.encode();
    // skip past parent_hash, number, state_root, extrinsics_root
    position += 32 + number_encoded.len() + 32 + 32;

    for log in header.digest.logs {
        let log_clone_2 = log.clone();
        if let DigestItem::Consensus(consensus_id, value) = log {
            if consensus_id == [70, 82, 78, 75] {
                println!("log {:?}", hex::encode(log_clone_2.encode()));

                println!("position {:?}", position);
                // TODO: have to figure out what value[0,1,2] means?
                println!("value prefix {:?}", &value[..3]);
                assert_eq!(value[0], 1); // To denote that it is a `ScheduledChange`
                let mut cursor = 3;
                let value_authories = &value[cursor..];
                println!("len {:?}", value_authories.len());
                let mut num_authorities = 0;
                for (i, authority_chunk) in value_authories.chunks_exact(32 + 8).enumerate() {
                    let pubkey = &authority_chunk[..32];
                    let weight = &authority_chunk[32..];

                    assert_eq!(*pubkey, authorities.1[i]);
                    // println!("pubkey {:?}", pubkey);
                    // println!("weight {:?}", weight);
                    // Assert weight's LE representation == 1
                    for j in 0..8 {
                        if j == 0 {
                            assert_eq!(weight[j], 1);
                        } else {
                            assert_eq!(weight[j], 0);
                        }
                    }

                    cursor += 32 + 8;
                    num_authorities += 1;
                }
                let delay = &value[cursor..];
                println!("delay {:?}", delay);
                println!("num_authorities {:?}", num_authorities);
                // verify header[position..position+4] == [70, 82, 78, 75]
                // verify header[position+4] == 1
                // verify header[position+5..position+5+2] == random stuff, TODO what is this
                // hash(header[position+5+2..position+5+2+num_authorities*(32+8)])
                // verify[position+5+2+num_authorities*(32+8)..+4] == [0, 0, 0, 0] // delay = 0
                break;
            }
        } else {
            let encoded = log.encode();
            println!("encoded {:?}", encoded);
            position += encoded.len();
        }
    }

    // let authority_set_hash_input = authorities
    //     .1
    //     .clone()
    //     .into_iter()
    //     .flatten()
    //     .collect::<Vec<_>>();
    // // TODO: Return authority_set_commitment to verify validity.
    // let authority_set_commitment =
    //     avail_subxt::config::substrate::BlakeTwo256::hash(&authority_set_hash_input);

    let end_position = position + ((32 + 8) * authorities.1.len()) + 4;

    (authorities.1.len(), position, end_position)
}

// Fetch a single header.
#[derive(Debug, Clone, Serialize, Deserialize, Send)]
pub struct RotateHint<const HEADER_LENGTH: usize> {}

#[async_trait]
impl<const HEADER_LENGTH: usize, L: PlonkParameters<D>, const D: usize> AsyncHint<L, D>
    for RotateHint<HEADER_LENGTH>
{
    async fn hint(
        &self,
        input_stream: &mut ValueStream<L, D>,
        output_stream: &mut ValueStream<L, D>,
    ) {
        let block_number = input_stream.read_value::<U32Variable>();

        debug!(
            "SingleHeaderFetcherHint: downloading header range of block={}",
            block_number
        );

        let data_fetcher = RpcDataFetcher::new().await;

        let header = data_fetcher.get_header(block_number).await;

        // TODO: replace with `to_header_variable` from vars.rs
        let mut header_bytes = header.encode();
        let header_size = header_bytes.len();
        if header_size > HEADER_LENGTH {
            panic!(
                "header size {} is greater than HEADER_LENGTH {}",
                header_size, HEADER_LENGTH
            );
        }
        header_bytes.resize(HEADER_LENGTH, 0);
        let header_variable = EncodedHeader {
            header_bytes,
            header_size: L::Field::from_canonical_usize(header_size),
        };

        // TODO: Use get_fixed_subarray

        let (num_authorities, position, end_position) = parse_single_header_rotate(header).await;

        // Encoded header.
        output_stream.write_value::<EncodedHeaderVariable<HEADER_LENGTH>>(header_variable);

        // Number of authorities.
        output_stream.write_value::<Variable>(L::Field::from_canonical_usize(num_authorities));

        // Start of consensus log.
        output_stream.write_value::<Variable>(L::Field::from_canonical_usize(position));

        // End position.
        output_stream.write_value::<Variable>(L::Field::from_canonical_usize(end_position));
    }
}

#[derive(Clone, Debug)]
pub struct RotateCircuit<
    const MAX_AUTHORITY_SET_SIZE: usize,
    const MAX_HEADER_LENGTH: usize,
    const MAX_CHUNKS_AUTHORITY_SET: usize,
    const MAX_NUM_HEADERS: usize,
> {}

impl<
        const MAX_AUTHORITY_SET_SIZE: usize,
        const MAX_HEADER_LENGTH: usize,
        const MAX_CHUNKS_AUTHORITY_SET: usize,
        const MAX_NUM_HEADERS: usize,
    > Circuit
    for RotateCircuit<
        MAX_AUTHORITY_SET_SIZE,
        MAX_HEADER_LENGTH,
        MAX_CHUNKS_AUTHORITY_SET,
        MAX_NUM_HEADERS,
    >
{
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        // Read the on-chain inputs.
        // Old authority set id
        let authority_set_id = builder.evm_read::<U64Variable>();
        builder.watch_with_level(
            &authority_set_id,
            "rotate circuit input - authority set id",
            Level::Debug,
        );

        // Old authority set hash
        let authority_set_hash = builder.evm_read::<Bytes32Variable>();
        builder.watch_with_level(
            &authority_set_hash,
            "rotate circuit input - authority set hash",
            Level::Debug,
        );

        let epoch_end_block_number = builder.evm_read::<U32Variable>();
        builder.watch_with_level(
            &epoch_end_block_number,
            "rotate circuit input - target block",
            Level::Debug,
        );

        // Fetch the header at epoch_end_block.
        let header_fetcher = RotateHint::<MAX_HEADER_LENGTH> {};
        let mut input_stream = VariableStream::new();
        input_stream.write(&epoch_end_block_number);
        let output_stream = builder.async_hint(input_stream, header_fetcher);

        let target_header = output_stream.read::<EncodedHeaderVariable<MAX_HEADER_LENGTH>>(builder);
        let num_authorities = output_stream.read::<Variable>(builder);
        let start_position = output_stream.read::<Variable>(builder);
        let end_position = output_stream.read::<Variable>(builder);

        // Hash the header at epoch_end_block.
        let target_header_hash =
            builder.hash_encoded_header::<MAX_HEADER_LENGTH, MAX_HEADER_CHUNK_SIZE>(&target_header);

        // Call rotate on the header.
        let new_authority_set_hash = builder
            .rotate::<MAX_HEADER_LENGTH, MAX_AUTHORITY_SET_SIZE, MAX_CHUNKS_AUTHORITY_SET>(
                &target_header,
                &target_header_hash,
                &num_authorities,
                &start_position,
                &end_position,
            );

        // Verify the epoch end block header is valid.
        builder.verify_simple_justification::<MAX_AUTHORITY_SET_SIZE>(
            epoch_end_block_number,
            target_header_hash,
            authority_set_id,
            authority_set_hash,
        );

        // TODO: Write the hash of the authority set to the output
        builder.evm_write::<Bytes32Variable>(new_authority_set_hash);
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(
        generator_registry: &mut plonky2x::prelude::HintRegistry<L, D>,
    ) where
        <<L as PlonkParameters<D>>::Config as plonky2::plonk::config::GenericConfig<D>>::Hasher:
            plonky2::plonk::config::AlgebraicHasher<L::Field>,
    {
        generator_registry.register_async_hint::<RotateHint<MAX_HEADER_LENGTH>>();
        generator_registry.register_hint::<HintSimpleJustification<MAX_AUTHORITY_SET_SIZE>>();

        let floor_div_id = FloorDivGenerator::<L::Field, D>::id();
        generator_registry.register_simple::<FloorDivGenerator<L::Field, D>>(floor_div_id);
    }
}

#[cfg(test)]
mod tests {
    use std::env;

    use ethers::types::H256;
    use plonky2x::prelude::{DefaultBuilder, GateRegistry, HintRegistry};

    use super::*;
    use crate::consts::MAX_HEADER_SIZE;

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_rotate_serialization() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 4;
        const MAX_HEADER_LENGTH: usize = MAX_HEADER_SIZE;
        const MAX_AUTHORITY_CHUNKS: usize = 30;
        const NUM_HEADERS: usize = 36;

        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        RotateCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, MAX_AUTHORITY_CHUNKS, NUM_HEADERS>::define(
            &mut builder,
        );
        let circuit = builder.build();
        log::debug!("Done building circuit");

        let mut hint_registry = HintRegistry::new();
        let mut gate_registry = GateRegistry::new();
        RotateCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, NUM_HEADERS, NUM_HEADERS>::register_generators(
            &mut hint_registry,
        );
        RotateCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, NUM_HEADERS, NUM_HEADERS>::register_gates(
            &mut gate_registry,
        );

        circuit.test_serializers(&gate_registry, &hint_registry);
    }

    #[test]
    #[cfg_attr(feature = "ci", ignore)]
    fn test_rotate_1() {
        env::set_var("RUST_LOG", "debug");
        env_logger::try_init().unwrap_or_default();

        const NUM_AUTHORITIES: usize = 100;
        const MAX_HEADER_LENGTH: usize = MAX_HEADER_SIZE;
        const MAX_AUTHORITY_CHUNKS: usize = 30;
        const NUM_HEADERS: usize = 36;
        let mut builder = DefaultBuilder::new();

        log::debug!("Defining circuit");
        RotateCircuit::<NUM_AUTHORITIES, MAX_HEADER_LENGTH, MAX_AUTHORITY_CHUNKS, NUM_HEADERS>::define(&mut builder);

        log::debug!("Building circuit");
        let circuit = builder.build();
        log::debug!("Done building circuit");

        // These inputs are taken from: https://kate.avail.tools/#/explorer/query/485710
        let mut input = circuit.input();
        let authority_set_id = 299u64;
        let authority_set_hash: [u8; 32] = [0u8; 32]; // Placeholder for now
        let epoch_end_block_number = 318937u32;

        input.evm_write::<U64Variable>(authority_set_id);
        input.evm_write::<Bytes32Variable>(H256::from_slice(authority_set_hash.as_slice()));
        input.evm_write::<U32Variable>(epoch_end_block_number);

        log::debug!("Generating proof");
        let (proof, mut output) = circuit.prove(&input);
        log::debug!("Done generating proof");

        circuit.verify(&proof, &input, &output);
        let new_authority_set_hash = output.evm_read::<Bytes32Variable>();
        println!("new_authority_set_hash {:?}", new_authority_set_hash);
    }
}
