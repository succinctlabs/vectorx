use std::{io::Cursor, marker::PhantomData};

use plonky2::{plonk::config::{GenericConfig, GenericHashOut, Hasher}, hash::{poseidon::{PoseidonHash, PoseidonPermutation}, hash_types::RichField}};
use plonky2_field::{goldilocks_field::GoldilocksField, extension::quadratic::QuadraticExtension, types::Field};
use serde::{Serialize, Deserialize};

use ff::{PrimeField, PrimeFieldRepr, Field as ff_Field};

use crate::{Fr, FrRepr};
use crate::poseidon_bn128::{permution, RATE};

/// Poseidon hash function.

/// Configuration using Poseidon over the Goldilocks field.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Serialize)]
pub struct PoseidonBN128GoldilocksConfig;
impl GenericConfig<2> for PoseidonBN128GoldilocksConfig {
    type F = GoldilocksField;
    type FE = QuadraticExtension<Self::F>;
    type Hasher = PoseidonBN128Hash;
    type InnerHasher = PoseidonHash;
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PoseidonBN128HashOut<F: Field> {
    limbs: [u64; 4],
    _phantom: PhantomData<F>,
}

fn hash_out_to_fr<F: Field>(hash: PoseidonBN128HashOut<F>) -> Fr {
    let bytes = [
        &hash.limbs[0].to_le_bytes()[..],
        &hash.limbs[1].to_le_bytes()[..],
        &hash.limbs[2].to_le_bytes()[..],
        &hash.limbs[3].to_le_bytes()[..],
   ].concat();

    let mut fr_repr: FrRepr = Default::default();
    fr_repr.read_le(Cursor::new(bytes.as_slice())).unwrap();
    Fr::from_repr(fr_repr).unwrap()
}

impl<F: RichField> GenericHashOut<F> for PoseidonBN128HashOut<F> {
    fn to_bytes(&self) -> Vec<u8> {
        [
            &self.limbs[0].to_le_bytes()[..],
            &self.limbs[1].to_le_bytes()[..],
            &self.limbs[2].to_le_bytes()[..],
            &self.limbs[3].to_le_bytes()[..],
        ].concat()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let limb0 = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let limb1 = u64::from_le_bytes(bytes[8..16].try_into().unwrap());
        let limb2 = u64::from_le_bytes(bytes[16..24].try_into().unwrap());
        let limb3 = u64::from_le_bytes(bytes[24..32].try_into().unwrap());

        Self {
            limbs: [limb0, limb1, limb2, limb3],
            _phantom: PhantomData,
        }
    }

    fn to_vec(&self) -> Vec<F> {
        let bytes = [
            &self.limbs[0].to_le_bytes()[..],
            &self.limbs[1].to_le_bytes()[..],
            &self.limbs[2].to_le_bytes()[..],
            &self.limbs[3].to_le_bytes()[..],
       ].concat();
        bytes
            // Chunks of 7 bytes since 8 bytes would allow collisions.
            .chunks(7)
            .map(|bytes| {
                let mut arr = [0; 8];
                arr[..bytes.len()].copy_from_slice(bytes);
                F::from_canonical_u64(u64::from_le_bytes(arr))
            })
            .collect()
    }
}


#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PoseidonBN128Hash;
impl<F: RichField> Hasher<F> for PoseidonBN128Hash {
    const HASH_SIZE: usize = Fr::NUM_BITS as usize / 8;
    type Hash = PoseidonBN128HashOut<F>;
    type Permutation = PoseidonPermutation<F>;

    fn hash_no_pad(input: &[F]) -> Self::Hash {
        let mut state = [Fr::zero(); 4];

        state[0] = Fr::zero();
        for rate_chunk in input.chunks(RATE * 3) {
            
            for (j, bn128_chunk)in rate_chunk.chunks(3).enumerate() {
                let mut bytes = bn128_chunk[0].to_canonical_u64().to_le_bytes().to_vec();

                for gl_element in bn128_chunk.iter().skip(1) {
                    let chunk_bytes = gl_element.to_canonical_u64().to_le_bytes();
                    bytes.extend_from_slice(&chunk_bytes);
                }

                for _i in bytes.len()..32 {
                    bytes.push(0);
                }

                let mut fr_repr: FrRepr = Default::default();
                fr_repr.read_le(bytes.as_slice()).unwrap();
                state[j+1] = Fr::from_repr(fr_repr).unwrap();
            }
            permution(&mut state);
        }

        PoseidonBN128HashOut{
            limbs: state[0].into_repr().0,
            _phantom: PhantomData,
        }
    }

    fn hash_pad(input: &[F]) -> Self::Hash {
        let mut padded_input = input.to_vec();
        padded_input.push(F::ONE);
        while (padded_input.len() + 1) % (RATE*3) != 0 {
            padded_input.push(F::ZERO);
        }
        padded_input.push(F::ONE);
        Self::hash_no_pad(&padded_input)
    }

    fn hash_or_noop(inputs: &[F]) -> Self::Hash {
        if inputs.len() * 8 <= 32 {
            let mut inputs_bytes = vec![0u8; 32];
            for i in 0..inputs.len() {
                inputs_bytes[i * 8..(i + 1) * 8]
                    .copy_from_slice(&inputs[i].to_canonical_u64().to_le_bytes());
            }
            PoseidonBN128HashOut::from_bytes(&inputs_bytes)
        } else {
            Self::hash_no_pad(inputs)
        }
    }

    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        let left_fr = hash_out_to_fr(left);
        let right_fr = hash_out_to_fr(right);

        let mut state = [Fr::zero(), Fr::zero(), left_fr, right_fr];
        permution(&mut state);

        PoseidonBN128HashOut{
            limbs: state[0].into_repr().0,
            _phantom: PhantomData,
        }
    }
}