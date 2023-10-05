use avail_plonky2x::subchain_verification_map_reduce::SubchainVerificationMRCircuit;
use plonky2x::backend::function::VerifiableFunction;

pub fn main() {
    VerifiableFunction::<SubchainVerificationMRCircuit>::entrypoint();
}
