use avail_plonky2x::subchain_verification::{
    SubChainVerifier, SubchainVerificationCtx, BATCH_SIZE,
};
use plonky2::plonk::config::{AlgebraicHasher, GenericConfig};
use plonky2x::backend::circuit::{Circuit, PlonkParameters};
use plonky2x::backend::function::VerifiableFunction;
use plonky2x::frontend::mapreduce::generator::MapReduceGenerator;
use plonky2x::frontend::vars::U32Variable;
use plonky2x::prelude::{Bytes32Variable, CircuitBuilder, HintRegistry, Variable};

pub struct SubchainVerificationMRCircuit;

impl Circuit for SubchainVerificationMRCircuit {
    fn define<L: PlonkParameters<D>, const D: usize>(builder: &mut CircuitBuilder<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher:
            AlgebraicHasher<<L as PlonkParameters<D>>::Field>,
    {
        let trusted_block = builder.evm_read::<U32Variable>();
        let trusted_header_hash = builder.evm_read::<Bytes32Variable>();
        let target_block = builder.evm_read::<U32Variable>();

        // Currently assuming that target_block - trusted_block <= MAX_EPOCH_SIZE
        let (target_header_hash, _, _) =
            builder.verify_subchain(trusted_block, trusted_header_hash, target_block);
        builder.watch(&target_header_hash, "target header hash");
    }

    fn register_generators<L: PlonkParameters<D>, const D: usize>(registry: &mut HintRegistry<L, D>)
    where
        <<L as PlonkParameters<D>>::Config as GenericConfig<D>>::Hasher: AlgebraicHasher<L::Field>,
    {
        let id = MapReduceGenerator::<
            L,
            SubchainVerificationCtx,
            U32Variable,
            (
                Variable,
                U32Variable,
                Bytes32Variable,
                Bytes32Variable,
                U32Variable,
                Bytes32Variable,
                Bytes32Variable,
                Bytes32Variable,
            ),
            BATCH_SIZE,
            D,
        >::id();
        registry.register_simple::<MapReduceGenerator<
            L,
            SubchainVerificationCtx,
            U32Variable,
            (
                Variable,
                U32Variable,
                Bytes32Variable,
                Bytes32Variable,
                U32Variable,
                Bytes32Variable,
                Bytes32Variable,
                Bytes32Variable,
            ),
            BATCH_SIZE,
            D,
        >>(id);
    }
}

pub fn main() {
    VerifiableFunction::<SubchainVerificationMRCircuit>::entrypoint();
}

#[cfg(test)]
mod tests {
    // use ethers::types::H256;
    use plonky2x::prelude::DefaultParameters;

    use super::*;

    type L = DefaultParameters;
    const D: usize = 2;

    #[test]
    fn test_circuit() {
        env_logger::try_init().unwrap_or_default();

        let mut builder = CircuitBuilder::<L, D>::new();
        SubchainVerificationMRCircuit::define(&mut builder);
        let circuit = builder.build();

        let mut input = circuit.input();
        let trusted_header: [u8; 32] =
            hex::decode("4cfd147756de6e8004a5f2ba9f2ca29e8488bae40acb97474c7086c45b39ff92")
                .unwrap()
                .try_into()
                .unwrap();
        let trusted_block = 272503u32;
        let target_block = 272535u32; // mimics test_step_small

        input.evm_write::<U32Variable>(trusted_block);
        input.evm_write::<Bytes32Variable>(H256::from_slice(trusted_header.as_slice()));
        input.evm_write::<U32Variable>(target_block);

        let (proof, output) = circuit.prove(&input);
        circuit.verify(&proof, &input, &output);

        SubchainVerificationMRCircuit::test_serialization::<L, D>();
    }
}
