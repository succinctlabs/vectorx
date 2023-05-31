use std::io::{BufWriter, BufReader, Cursor};

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

fn fr_to_bytes(value: Fr) -> Vec<u8> {
    let mut buf = BufWriter::new(Vec::new());
    let value_fr_repr: FrRepr = value.into_repr();
    value_fr_repr.write_be(&mut buf).unwrap();
    buf.get_ref().clone()
}

fn hash_out_to_fr(hash: PoseidonBN128HashOut) -> Fr {
    let bytes = [
        &hash.0[0].to_be_bytes()[..],
        &hash.0[1].to_be_bytes()[..],
        &hash.0[2].to_be_bytes()[..],
        &hash.0[3].to_be_bytes()[..],
   ].concat();

    let mut fr_repr: FrRepr = Default::default();
    fr_repr.read_be(Cursor::new(bytes.as_slice())).unwrap();
    Fr::from_repr(fr_repr).unwrap()
}

impl<F: RichField> GenericHashOut<F> for PoseidonBN128HashOut {
    fn to_bytes(&self) -> Vec<u8> {
        fr_to_bytes(self.0)
    }

    fn from_bytes(bytes: &[u8]) -> Self {
        let buf = BufReader::new(bytes);
        let mut value: FrRepr = Default::default();
        value.read_be(buf).unwrap();
        Self(Fr::from_repr(value).unwrap())
    }

    fn to_vec(&self) -> Vec<F> {
        let bytes = fr_to_bytes(self.0);
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
                let mut large_value = bn128_chunk[0].to_canonical_biguint();

                for i in 1..bn128_chunk.len() {
                    let small_value = bn128_chunk[i].to_canonical_biguint();
                    large_value = large_value << 64 | small_value;
                }

                /*  TODO:  Get this working
                let large_value_be = large_value.to_bytes_be();
                println!("large_value_be: {:?}", large_value_be);
                let large_value_reader = Cursor::new(large_value_be.as_slice());
                let mut large_value_fr_repr: FrRepr = Default::default();
                large_value_fr_repr.read_be(large_value_reader).unwrap();
                */

                let large_value_str = large_value.to_string();
                state[chunk_idx] = Fr::from_str(&large_value_str).unwrap();
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