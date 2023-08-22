use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{GeneratedValues, SimpleGenerator};
use plonky2::iop::target::Target;
use plonky2::iop::witness::{PartitionWitness, Witness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::util::serialization::{Buffer, IoResult, Read, Write};
use plonky2::{
    field::{
        extension::Extendable,
        types::{PrimeField, PrimeField64},
    },
    plonk::circuit_data::CommonCircuitData,
};
use std::marker::PhantomData;

pub const NUM_AUTHORITIES: usize = 76;
pub const NUM_AUTHORITIES_PADDED: usize = 128; // The random access gadget requires a power of 2, so we pad the authority set to 128
pub const QUORUM_SIZE: usize = 51; // 2/3 + 1 of NUM_VALIDATORS

pub const CHUNK_128_BYTES: usize = 128;
pub const MAX_HEADER_SIZE: usize = CHUNK_128_BYTES * 103; // 2048 bytes
pub const HASH_SIZE: usize = 32; // in bytes
pub const PUB_KEY_SIZE: usize = 32; // in bytes

pub const ENCODED_PRECOMMIT_LENGTH: usize = 53;

#[derive(Debug, Clone)]
pub struct AvailHashTarget(pub [Target; HASH_SIZE]);

impl From<[Target; HASH_SIZE]> for AvailHashTarget {
    fn from(elements: [Target; HASH_SIZE]) -> Self {
        Self(elements)
    }
}

pub trait WitnessAvailHash<F: PrimeField64>: Witness<F> {
    fn get_avail_hash_target(&self, target: AvailHashTarget) -> [u8; HASH_SIZE];
    fn set_avail_hash_target(&mut self, target: &AvailHashTarget, value: &[u8; HASH_SIZE]);
}

impl<T: Witness<F>, F: PrimeField64> WitnessAvailHash<F> for T {
    fn get_avail_hash_target(&self, target: AvailHashTarget) -> [u8; HASH_SIZE] {
        target
            .0
            .iter()
            .map(|t| u8::try_from(self.get_target(*t).to_canonical_u64()).unwrap())
            .collect::<Vec<u8>>()
            .try_into()
            .unwrap()
    }

    fn set_avail_hash_target(&mut self, target: &AvailHashTarget, value: &[u8; HASH_SIZE]) {
        for (i, hash_byte) in value.iter().enumerate().take(HASH_SIZE) {
            self.set_target(target.0[i], F::from_canonical_u8(*hash_byte));
        }
    }
}

pub trait GeneratedValuesAvailHash<F: PrimeField> {
    fn set_avail_hash_target(&mut self, target: &AvailHashTarget, value: [u8; HASH_SIZE]);
}

impl<F: PrimeField> GeneratedValuesAvailHash<F> for GeneratedValues<F> {
    fn set_avail_hash_target(&mut self, target: &AvailHashTarget, value: [u8; HASH_SIZE]) {
        for (i, hash_byte) in value.iter().enumerate().take(HASH_SIZE) {
            self.set_target(target.0[i], F::from_canonical_u8(*hash_byte));
        }
    }
}

#[derive(Clone, Debug)]
pub struct EncodedHeaderTarget {
    pub header_bytes: [Target; MAX_HEADER_SIZE],
    pub header_size: Target,
}

pub trait WitnessEncodedHeader<F: PrimeField64>: Witness<F> {
    fn get_encoded_header_target(&self, target: EncodedHeaderTarget) -> Vec<u8>;
    fn set_encoded_header_target(&mut self, target: &EncodedHeaderTarget, value: Vec<u8>);
}

impl<T: Witness<F>, F: PrimeField64> WitnessEncodedHeader<F> for T {
    fn get_encoded_header_target(&self, target: EncodedHeaderTarget) -> Vec<u8> {
        let header_size = self.get_target(target.header_size).to_canonical_u64();
        target
            .header_bytes
            .iter()
            .take(header_size as usize)
            .map(|t| u8::try_from(self.get_target(*t).to_canonical_u64()).unwrap())
            .collect::<Vec<u8>>()
    }

    fn set_encoded_header_target(&mut self, target: &EncodedHeaderTarget, value: Vec<u8>) {
        let header_size = value.len();
        self.set_target(
            target.header_size,
            F::from_canonical_u64(header_size as u64),
        );
        for (i, byte) in value.iter().enumerate().take(header_size) {
            self.set_target(target.header_bytes[i], F::from_canonical_u8(*byte));
        }

        for i in header_size..MAX_HEADER_SIZE {
            self.set_target(target.header_bytes[i], F::from_canonical_u8(0));
        }
    }
}

pub trait GeneratedValuesEncodedHeader<F: PrimeField> {
    fn set_encoded_header_target(&mut self, target: &EncodedHeaderTarget, value: Vec<u8>);
}

impl<F: PrimeField> GeneratedValuesEncodedHeader<F> for GeneratedValues<F> {
    fn set_encoded_header_target(&mut self, target: &EncodedHeaderTarget, value: Vec<u8>) {
        let header_size = value.len();
        self.set_target(
            target.header_size,
            F::from_canonical_u64(header_size as u64),
        );
        for (i, byte) in value.iter().enumerate().take(header_size) {
            self.set_target(target.header_bytes[i], F::from_canonical_u8(*byte));
        }

        for i in header_size..MAX_HEADER_SIZE {
            self.set_target(target.header_bytes[i], F::from_canonical_u8(0));
        }
    }
}

pub trait CircuitBuilderUtils {
    fn add_virtual_avail_hash_target_safe(&mut self, set_as_public: bool) -> AvailHashTarget;

    fn add_virtual_encoded_header_target_safe(&mut self) -> EncodedHeaderTarget;

    fn int_div(&mut self, dividend: Target, divisor: Target) -> Target;

    fn connect_avail_hash(&mut self, x: AvailHashTarget, y: AvailHashTarget);

    fn random_access_avail_hash(
        &mut self,
        index: Target,
        targets: Vec<AvailHashTarget>,
    ) -> AvailHashTarget;
}

impl<F: RichField + Extendable<D>, const D: usize> CircuitBuilderUtils for CircuitBuilder<F, D> {
    fn add_virtual_avail_hash_target_safe(&mut self, set_as_public: bool) -> AvailHashTarget {
        let mut hash_target = Vec::new();
        for _ in 0..HASH_SIZE {
            let byte = self.add_virtual_target();
            if set_as_public {
                self.register_public_input(byte);
            }
            self.range_check(byte, 8);
            hash_target.push(byte);
        }

        AvailHashTarget(hash_target.try_into().unwrap())
    }

    fn add_virtual_encoded_header_target_safe(&mut self) -> EncodedHeaderTarget {
        let mut header_bytes = Vec::new();
        for _j in 0..MAX_HEADER_SIZE {
            let byte = self.add_virtual_target();
            self.range_check(byte, 8);
            header_bytes.push(byte);
        }

        let header_size = self.add_virtual_target();

        EncodedHeaderTarget {
            header_bytes: header_bytes.try_into().unwrap(),
            header_size,
        }
    }

    fn connect_avail_hash(&mut self, x: AvailHashTarget, y: AvailHashTarget) {
        for i in 0..HASH_SIZE {
            self.connect(x.0[i], y.0[i]);
        }
    }

    fn int_div(&mut self, dividend: Target, divisor: Target) -> Target {
        let quotient = self.add_virtual_target();
        let remainder = self.add_virtual_target();

        self.add_simple_generator(FloorDivGenerator::<F, D> {
            divisor,
            dividend,
            quotient,
            remainder,
            _marker: PhantomData,
        });
        let base = self.mul(quotient, divisor);
        let rhs = self.add(base, remainder);
        let is_equal = self.is_equal(rhs, dividend);
        self.assert_one(is_equal.target);
        quotient
    }

    fn random_access_avail_hash(
        &mut self,
        access_index: Target,
        v: Vec<AvailHashTarget>,
    ) -> AvailHashTarget {
        let selected = core::array::from_fn(|i| {
            self.random_access(access_index, v.iter().map(|hash| hash.0[i]).collect())
        });
        selected.into()
    }
}

#[derive(Debug)]
struct FloorDivGenerator<F: RichField + Extendable<D>, const D: usize> {
    divisor: Target,
    dividend: Target,
    quotient: Target,
    remainder: Target,
    _marker: PhantomData<F>,
}

impl<F: RichField + Extendable<D>, const D: usize> SimpleGenerator<F, D>
    for FloorDivGenerator<F, D>
{
    fn id(&self) -> String {
        "FloorDivGenerator".to_string()
    }

    fn serialize(&self, dst: &mut Vec<u8>, _common_data: &CommonCircuitData<F, D>) -> IoResult<()> {
        dst.write_target(self.divisor)?;
        dst.write_target(self.dividend)?;
        dst.write_target(self.quotient)?;
        dst.write_target(self.remainder)
    }

    fn deserialize(src: &mut Buffer, _common_data: &CommonCircuitData<F, D>) -> IoResult<Self> {
        let divisor = src.read_target()?;
        let dividend = src.read_target()?;
        let quotient = src.read_target()?;
        let remainder = src.read_target()?;
        Ok(Self {
            divisor,
            dividend,
            quotient,
            remainder,
            _marker: PhantomData,
        })
    }

    fn dependencies(&self) -> Vec<Target> {
        Vec::from([self.dividend])
    }

    fn run_once(&self, witness: &PartitionWitness<F>, out_buffer: &mut GeneratedValues<F>) {
        let divisor = witness.get_target(self.divisor);
        let dividend = witness.get_target(self.dividend);
        let divisor_int = divisor.to_canonical_u64() as u32;
        let dividend_int = dividend.to_canonical_u64() as u32;
        let quotient = dividend_int / divisor_int;
        let remainder = dividend_int % divisor_int;
        out_buffer.set_target(self.quotient, F::from_canonical_u32(quotient));
        out_buffer.set_target(self.remainder, F::from_canonical_u32(remainder));
    }
}

// Will convert each byte into 8 bits (big endian)
pub fn to_bits(msg: Vec<u8>) -> Vec<bool> {
    let mut res = Vec::new();
    for char in msg.iter() {
        for j in 0..8 {
            if (char & (1 << (7 - j))) != 0 {
                res.push(true);
            } else {
                res.push(false);
            }
        }
    }
    res
}
