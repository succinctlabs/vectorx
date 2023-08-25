#![allow(clippy::too_many_arguments)]

mod decoder;
mod header;
mod justification;
mod plonky2_config;
mod poseidon_bn128;
mod poseidon_bn128_constants;
//pub mod step;
mod subchain_verification;
mod testing_utils;
mod utils;

extern crate ff;
extern crate rand;
use ff::Field;
use ff::PrimeField;
use ff::PrimeFieldRepr;

#[derive(PrimeField)]
#[PrimeFieldModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[PrimeFieldGenerator = "7"]

pub struct Fr(FrRepr);
