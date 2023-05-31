use std::io::Cursor;

use plonky2::{plonk::config::{GenericConfig, GenericHashOut, Hasher}, hash::{poseidon::{PoseidonHash, PoseidonPermutation}, hash_types::RichField}};
use plonky2_field::{goldilocks_field::GoldilocksField, extension::quadratic::QuadraticExtension};
use poseidon_rs::{Fr, FrRepr, Poseidon};
use serde::{Serialize, Deserialize};

use ff_ce::{PrimeField, PrimeFieldRepr};

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
pub struct PoseidonBN128HashOut([u64; 4]);

fn hash_out_to_fr(hash: PoseidonBN128HashOut) -> Fr {
    let bytes = [
        &hash.0[0].to_le_bytes()[..],
        &hash.0[1].to_le_bytes()[..],
        &hash.0[2].to_le_bytes()[..],
        &hash.0[3].to_le_bytes()[..],
   ].concat();

    let mut fr_repr: FrRepr = Default::default();
    fr_repr.read_le(Cursor::new(bytes.as_slice())).unwrap();
    Fr::from_repr(fr_repr).unwrap()
}

impl<F: RichField> GenericHashOut<F> for PoseidonBN128HashOut {
    fn to_bytes(&self) -> Vec<u8> {
        [
            &self.0[0].to_le_bytes()[..],
            &self.0[1].to_le_bytes()[..],
            &self.0[2].to_le_bytes()[..],
            &self.0[3].to_le_bytes()[..],
        ].concat()
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let limb0 = u64::from_le_bytes(bytes[0..4].try_into().unwrap());
        let limb1 = u64::from_le_bytes(bytes[4..8].try_into().unwrap());
        let limb2 = u64::from_le_bytes(bytes[8..12].try_into().unwrap());
        let limb3 = u64::from_le_bytes(bytes[12..16].try_into().unwrap());

        Self([limb0, limb1, limb2, limb3])
    }

    fn to_vec(&self) -> Vec<F> {
        let bytes = [
            &self.0[0].to_le_bytes()[..],
            &self.0[1].to_le_bytes()[..],
            &self.0[2].to_le_bytes()[..],
            &self.0[3].to_le_bytes()[..],
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
    type Hash = PoseidonBN128HashOut;
    type Permutation = PoseidonPermutation<F>;

    fn hash_no_pad(input: &[F]) -> Self::Hash {
        // TODO: We can just have one instance of the poseidon hasher
        let psd = Poseidon::new();
        let mut state = [Fr::default(); 5].to_vec();
        for permute_chunk in input.chunks(12) {
            let mut chunk_idx = 0;
            for bn128_chunk in permute_chunk.chunks(3) {
                let mut bytes = bn128_chunk[0].to_canonical_u64().to_le_bytes().to_vec();

                for i in 1..bn128_chunk.len() {
                    let chunk_bytes = bn128_chunk[i].to_canonical_u64().to_le_bytes();
                    bytes.extend_from_slice(&chunk_bytes);
                }

                for _i in bytes.len()..32 {
                    bytes.push(0);
                }

                let mut fr_repr: FrRepr = Default::default();
                fr_repr.read_le(bytes.as_slice()).unwrap();
                state[chunk_idx] = Fr::from_repr(fr_repr).unwrap();
                chunk_idx += 1;
            };

            let hash = psd.hash(state.clone()).unwrap();
            state[4] = hash[0];
        };

        PoseidonBN128HashOut(state[0].into_repr().0)
    }

    fn two_to_one(left: Self::Hash, right: Self::Hash) -> Self::Hash {
        let left_fr = hash_out_to_fr(left);
        let right_fr = hash_out_to_fr(right);

        let state = vec![left_fr, right_fr, Fr::default(), Fr::default()];

        // TODO: We can just have one instance of the poseidon hasher
        let psd = Poseidon::new();
        PoseidonBN128HashOut(psd.hash(state).unwrap()[0].into_repr().0)
    }
}