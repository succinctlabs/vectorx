use avail_plonky2x::subchain_verification_map_reduce::MapReduceSubchainVerificationCircuit;
use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::VerifiableFunction;
use plonky2x::prelude::{CircuitBuilder, DefaultParameters};

pub fn main() {
    VerifiableFunction::<MapReduceSubchainVerificationCircuit>::entrypoint();
}
