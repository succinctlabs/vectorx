pub mod config;
pub mod decoder;
pub mod justification;
pub mod poseidon_bn128;
pub mod step;
pub mod utils;

extern crate rand;
extern crate ff;
use ff::PrimeField;
use ff::Field;
use ff::PrimeFieldRepr;

#[derive(PrimeField)]
#[PrimeFieldModulus = "21888242871839275222246405745257275088548364400416034343698204186575808495617"]
#[PrimeFieldGenerator = "7"]

pub struct Fr(FrRepr);