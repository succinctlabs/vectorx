use std::marker::PhantomData;
use itertools::izip;
use plonky2::hash::hash_types::RichField;
use plonky2::iop::generator::{SimpleGenerator, GeneratedValues};
use plonky2::iop::target::{Target, BoolTarget};
use plonky2::iop::witness::{PartitionWitness, Witness};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2_ecdsa::gadgets::biguint::BigUintTarget;
use plonky2_field::extension::Extendable;
use plonky2_u32::gadgets::arithmetic_u32::U32Target;

pub fn make_scale_header_circuit<F: RichField + Extendable<D>, const D: usize>(
    builder: &mut CircuitBuilder<F, D>,
    max_encoded_header_size: usize
) -> ScaleHeaderTarget
{
    let mut scale_header = ScaleHeaderTarget{ targets: Vec::with_capacity(max_encoded_header_size as usize) };

    for _i in 0..max_encoded_header_size {
        scale_header.targets.push(builder.add_virtual_target());
    }

    scale_header
}

// Scale Byte encoded representation of 
// Avail headers
pub struct ScaleHeaderTarget {
    targets: Vec<Target>,
}

impl ScaleHeaderTarget {
    pub fn get_encoded_header_target(&self) -> &Vec<Target> {
        &self.targets
    }

    pub fn get_parent_hash(&self) -> Vec<Target> {
        self.targets[0..32].to_vec()
    }

    pub fn get_number<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Target {
        // Can need up to 5 bytes to represent u32 compactly in SCALE
        let compact = self.targets[32..37].to_vec();

        // Compute compact_byte mod 4 to determine how many bytes to use
        let byte_mod = self.get_byte_mod(builder);
        let (compact_length, cb_cases) = self.get_compact_length(builder, byte_mod, compact);
        let length_branch = self.get_length_branch(builder, compact_length);

        // Determine whether to divide by four or not, based off
        // https://github.com/polkascan/py-scale-codec/blob/master/scalecodec/types.py#L113
        let dividend = builder.random_access(byte_mod, cb_cases.to_vec());
        let quotient = self.get_floor_div_by_four(builder, dividend);
        let res = builder.select(length_branch, quotient, dividend);
        res
    }

    fn get_byte_mod<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>
    ) -> Target {
        let compact_byte_limb = vec![U32Target(self.targets[32])];
        let compact_byte_biguint = BigUintTarget { limbs: compact_byte_limb };
        const B: usize = 4;
        let byte_mod_vec = builder.split_le_base::<B>(compact_byte_biguint.get_limb(0).0, 16);
        byte_mod_vec[0]
    }

    /// Compute compact length based on byte_mod, then return 
    /// compact length along with cases of which compact bytes to use for 
    /// later computation
    /// Python implementation: https://github.com/polkascan/py-scale-codec/blob/master/scalecodec/types.py#L45-L59
    fn get_compact_length<F: RichField + Extendable<D>, const D: usize>(
        &self, 
        builder: &mut CircuitBuilder<F, D>, 
        byte_mod: Target, 
        compact: Vec<Target>
    ) -> (Target, [Target; 4]) {
        let (cl_case_zero, cb_case_zero) = self.byte_mod_case_zero(builder, compact.clone());
        let (cl_case_one, cb_case_one) = self.byte_mod_case_one(builder, compact.clone());
        let (cl_case_two, cb_case_two) = self.byte_mod_case_two(builder, compact.clone());
        let (cl_case_three, cb_case_three) = self.byte_mod_case_three(builder, compact.clone());
        let cl_cases = [cl_case_zero, cl_case_one, cl_case_two, cl_case_three];
        let cb_cases = [cb_case_zero, cb_case_one, cb_case_two, cb_case_three];
        let compact_length = builder.random_access(byte_mod, cl_cases.to_vec());
        (compact_length, cb_cases)
    }

    /// Compute which branch to take based on compact length of encoding
    fn get_length_branch<F: RichField + Extendable<D>, const D: usize>(
        &self, 
        builder: &mut CircuitBuilder<F, D>, 
        compact_length: Target
    ) -> BoolTarget {
        let one = builder.constant(F::from_canonical_u8(1));
        let two = builder.constant(F::from_canonical_u8(2));
        let four = builder.constant(F::from_canonical_u8(4));
        let is_one = builder.is_equal(compact_length, one);
        let is_two = builder.is_equal(compact_length, two);
        let is_four = builder.is_equal(compact_length, four);
        let intermediate = builder.add(is_one.target, is_two.target);
        let condition_one = builder.add(intermediate, is_four.target);
        builder.is_equal(condition_one, one)
    }

    /// Helper to calculate integer division in a field
    /// Used in https://github.com/polkascan/py-scale-codec/blob/master/scalecodec/types.py#L113
    fn get_floor_div_by_four<F: RichField + Extendable<D>, const D: usize>(
        &self, 
        builder: &mut CircuitBuilder<F, D>, 
        dividend: Target,
    ) -> Target {
        let four = builder.constant(F::from_canonical_u8(4));
        let quotient = builder.add_virtual_target();
        let remainder = builder.add_virtual_target();

        builder.add_simple_generator(FloorDivGenerator::<F, D> {
            divisor: four,
            dividend,
            quotient,
            remainder,
            _marker: PhantomData
        });
        let base = builder.mul(quotient, four);
        let rhs = builder.add(base, remainder);
        let is_equal = builder.is_equal(rhs, dividend);
        builder.assert_one(is_equal.target);
        quotient
    }

    // Byte mod 0 case when decoding Scale CompactU32
    fn byte_mod_case_zero<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        compact: Vec<Target>
    ) -> (Target, Target) {
        let compact_length = builder.constant(F::from_canonical_u8(1));
        let compact_bytes = self.from_bytes_le(builder, vec![compact[0]]);
        (compact_length, compact_bytes)
    }

    // Byte mod 1 case when decoding Scale CompactU32
    fn byte_mod_case_one<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        compact: Vec<Target>
    ) -> (Target, Target) {
        let compact_length = builder.constant(F::from_canonical_u8(2));
        let compact_bytes = self.from_bytes_le(builder, compact[0..2].to_vec());
        (compact_length, compact_bytes)
    }

    // Byte mod 2 case when decoding Scale CompactU32
    fn byte_mod_case_two<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        compact: Vec<Target>
    ) -> (Target, Target) {
        let compact_length = builder.constant(F::from_canonical_u8(4));
        let compact_bytes = self.from_bytes_le(builder, compact[0..4].to_vec());
        (compact_length, compact_bytes)
    }

    // Byte mod 3 case when decoding Scale CompactU32
    fn byte_mod_case_three<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        compact: Vec<Target>
    ) -> (Target, Target) {
        let compact_length = builder.constant(F::from_canonical_u8(5));
        let compact_bytes = self.from_bytes_le(builder, compact[1..].to_vec());
        (compact_length, compact_bytes)
    }

    pub fn get_state_root<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let byte_mod = self.get_byte_mod(builder);
        let case_one = &(self.targets[33..65]);
        let case_two = &(self.targets[34..66]);
        let case_three = &(self.targets[37..69]);
        let case_four = &(self.targets[36..68]);
        self.random_access_vec(builder, byte_mod, case_one, case_two, case_three, case_four)
    }

    pub fn get_extrinsic_root<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Vec<Target> {
        let byte_mod = self.get_byte_mod(builder);
        let case_one = &(self.targets[65..97]);
        let case_two = &(self.targets[66..98]);
        let case_three = &(self.targets[69..101]);
        let case_four = &(self.targets[68..100]);
        self.random_access_vec(builder, byte_mod, case_one, case_two, case_three, case_four)
    }

    fn random_access_vec<F: RichField + Extendable<D>, const D: usize>(
        &self, 
        builder: &mut CircuitBuilder<F, D>,
        // b: BoolTarget, 
        index: Target,
        v0: &[Target],
        v1: &[Target],
        v2: &[Target],
        v3: &[Target],
    ) -> Vec<Target> {
        izip!(v0, v1, v2, v3)
            .map(|(t0, t1, t2, t3)| 
                    builder.random_access(index, vec![*t0, *t1, *t2, *t3]))
            .collect::<Vec<_>>()
    }

    fn from_bytes_le<F: RichField + Extendable<D>, const D: usize>(
        &self,
        builder: &mut CircuitBuilder<F, D>,
        targets: Vec<Target>
    ) -> Target {
        let base = builder.constant(F::from_canonical_usize(256));
        let mut pow = builder.constant(F::from_canonical_usize(1));
        let mut sum = builder.constant(F::from_canonical_usize(0));
        for i in 0..targets.len() {
            let curr = builder.mul(targets[i], pow);
            pow = builder.mul(pow, base);
            sum = builder.add(sum, curr);
        }
        sum
    }
}

#[derive(Debug)]
struct FloorDivGenerator<
    F: RichField + Extendable<D>,
    const D: usize
> {
    divisor: Target,
    dividend: Target,
    quotient: Target,
    remainder: Target,
    _marker: PhantomData<F>,
}

impl<
    F: RichField + Extendable<D>,
    const D: usize,
> SimpleGenerator<F> for FloorDivGenerator<F, D> {
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

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use codec::Encode;
    use rand::Rng;
    use plonky2::iop::witness::{PartialWitness, Witness};
    use plonky2::plonk::circuit_builder::CircuitBuilder;
    use plonky2::plonk::circuit_data::CircuitConfig;
    use plonky2::plonk::config::{GenericConfig, PoseidonGoldilocksConfig};
    use plonky2_field::types::Field;

    use crate::encoding::ScaleHeaderTarget;

    #[test]
    fn test_zero() -> Result<()>{
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let header_bytes = [0u8; 326];
        let mut header = ScaleHeaderTarget { targets: Vec::with_capacity(header_bytes.len()) };
        for _ in 0..header_bytes.len() {
            header.targets.push(builder.add_virtual_target());
        }
        for i in 0..header_bytes.len() {
            let felt = F::from_canonical_u8(header_bytes[i]);
            pw.set_target(header.targets[i], felt);
        }

        let number = header.get_number(&mut builder);
        let val = builder.constant(F::from_canonical_u8(0));
        builder.connect(number, val);
        
        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof)
    }

    #[test]
    fn test_one() -> Result<()>{
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut header_bytes = [0u8; 326];
        header_bytes[32] = 4;
        let mut header = ScaleHeaderTarget { targets: Vec::with_capacity(header_bytes.len()) };
        for _ in 0..header_bytes.len() {
            header.targets.push(builder.add_virtual_target());
        }
        for i in 0..header_bytes.len() {
            let felt = F::from_canonical_u8(header_bytes[i]);
            pw.set_target(header.targets[i], felt);
        }

        let number = header.get_number(&mut builder);
        let val = builder.constant(F::from_canonical_u8(1));
        builder.connect(number, val);
        
        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof)
    }

    #[test]
    fn test_avail_block() -> Result<()>{
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let mut header_bytes = [0u8; 326].to_vec();
        let slice = &[186u8, 220, 20, 0];
        header_bytes.splice(32..36, slice.iter().cloned());
        let mut header = ScaleHeaderTarget { targets: Vec::with_capacity(header_bytes.len()) };
        for _ in 0..header_bytes.len() {
            header.targets.push(builder.add_virtual_target());
        }
        for i in 0..header_bytes.len() {
            let felt = F::from_canonical_u8(header_bytes[i]);
            pw.set_target(header.targets[i], felt);
        }

        let number = header.get_number(&mut builder);
        let val = builder.constant(F::from_canonical_usize(341806));
        builder.connect(number, val);
        
        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof)
    }

    fn test_random_between_range(low: u32, high: u32) -> Result<()> {
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
        let config = CircuitConfig::standard_recursion_config();
        let mut pw = PartialWitness::new();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        let (r, r_enc) = rand_to_scale_bytes(low, high);

        let mut header_bytes = [0u8; 326].to_vec();
        let slice = &(r_enc[..]);
        header_bytes.splice(32..32+slice.len(), slice.iter().cloned());
        let mut header = ScaleHeaderTarget { targets: Vec::with_capacity(header_bytes.len()) };
        for _ in 0..header_bytes.len() {
            header.targets.push(builder.add_virtual_target());
        }
        for i in 0..header_bytes.len() {
            let felt = F::from_canonical_u8(header_bytes[i]);
            pw.set_target(header.targets[i], felt);
        }

        let number = header.get_number(&mut builder);
        let val = builder.constant(F::from_canonical_usize(r as usize));
        builder.connect(number, val);
        
        let data = builder.build::<C>();
        let proof = data.prove(pw)?;

        data.verify(proof)
    }

    #[test]
    fn test_random_case_one() -> Result<()> {
        test_random_between_range(0, 63+1)
    }

    #[test]
    fn test_random_case_two() -> Result<()> {
        test_random_between_range(64, 16383+1)
    }

    #[test]
    fn test_random_case_three() -> Result<()> {
        test_random_between_range(16384, 1073741823+1)
    }

    #[test]
    fn test_random_case_four() -> Result<()> {
        test_random_between_range(1073741824, u32::MAX)
    }

    fn rand_to_scale_bytes(low: u32, high: u32) -> (u32, Vec<u8>) {
        let mut rng = rand::thread_rng();
        let r = rng.gen_range(low..high);
        let s = ScaleNumber { number: r };
        (r, Encode::encode(&s))
    }

    #[derive(Debug, Clone, PartialEq, Eq, Encode)]
    struct ScaleNumber {
        #[codec(compact)]
        pub number: u32
    }
}
