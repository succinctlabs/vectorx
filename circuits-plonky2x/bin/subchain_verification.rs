use avail_plonky2x::subchain_verification_map_reduce::MapReduceSubchainVerificationCircuit;
use plonky2x::backend::circuit::Circuit;
use plonky2x::backend::function::VerifiableFunction;
use plonky2x::prelude::{CircuitBuilder, DefaultParameters};

pub fn main() {
    VerifiableFunction::<MapReduceSubchainVerificationCircuit>::entrypoint();
}

// RELEASE_ID=1ff12645-3f2a-459b-ad08-3e74e62c4075 PROVER=remote PROOF_SERVICE_URL=https://alpha.succinct.xyz cargo run --release --bin subchain_verification prove --input-json input.json


// RELEASE_ID=1ff12645-3f2a-459b-ad08-3e74e62c4075 PROVER=remote PROOF_SERVICE_URL=https://alpha.succinct.xyz cargo test --package avail_plonky2x --lib --release -- subchain_verification_map_reduce::tests --nocapture 
