use plonky2x::prelude::RichField;

trait FieldConversion<F: RichField> {
    fn to_u8(&self) -> Vec<u8>;
}

trait ByteConversion<F: RichField> {
    fn to_field(&self) -> Vec<F>;
}

impl<F: RichField> FieldConversion<F> for Vec<F> {
    fn to_u8(&self) -> Vec<u8> {
        self.iter()
            .map(|field| field.to_canonical_u64().try_into().unwrap())
            .collect()
    }
}

impl<F: RichField> ByteConversion<F> for Vec<u8> {
    fn to_field(&self) -> Vec<F> {
        self.iter()
            .map(|byte| F::from_canonical_u8(*byte))
            .collect()
    }
}
