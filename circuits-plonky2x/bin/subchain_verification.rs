use avail_plonky2x::subchain_verification_map_reduce::MapReduceSubchainVerificationCircuit;
use plonky2x::backend::circuit::Circuit;
use plonky2x::prelude::{CircuitBuilder, DefaultParameters};

pub fn main() {
    type L = DefaultParameters;
    const D: usize = 2;

    env_logger::try_init().unwrap_or_default();

    let mut builder = CircuitBuilder::<L, D>::new();
    MapReduceSubchainVerificationCircuit::define(&mut builder);
    let circuit = builder.build();

    let input = circuit.input();
    let (proof, output) = circuit.prove(&input);
    circuit.verify(&proof, &input, &output);
}
