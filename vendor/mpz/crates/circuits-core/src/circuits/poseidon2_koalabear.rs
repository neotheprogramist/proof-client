//! Stock Plonky3 width-16 KoalaBear Poseidon2 over Boolean gates.

use std::array::from_fn;

use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{
    GenericPoseidon2LinearLayersKoalaBear, KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL, KOALABEAR_POSEIDON2_RC_16_INTERNAL, KoalaBear,
};
use p3_poseidon2::GenericPoseidon2LinearLayers;

use crate::{BuilderError, Circuit, CircuitBuilder, Feed, Node, ops};

#[derive(Clone, Copy)]
struct Word([Node<Feed>; 31]);

impl Word {
    fn constant(builder: &CircuitBuilder, value: KoalaBear) -> Self {
        let value = value.as_canonical_u32();
        Self(from_fn(|i| {
            if value >> i & 1 == 0 {
                builder.get_const_zero()
            } else {
                builder.get_const_one()
            }
        }))
    }

    fn reduce_once(builder: &mut CircuitBuilder, bits: [Node<Feed>; 32]) -> Self {
        let modulus = from_fn::<_, 32, _>(|i| {
            if KoalaBear::ORDER_U32 >> i & 1 == 0 {
                builder.get_const_zero()
            } else {
                builder.get_const_one()
            }
        });
        let (difference, borrow) = ops::wrapping_sub(builder, &bits, &modulus);
        // PROOF: caller supplies a value below 2p; one subtraction yields a residue below p.
        Self(from_fn(|i| {
            let delta = builder.add_xor_gate(bits[i], difference[i]);
            let selected = builder.add_and_gate(delta, borrow);
            builder.add_xor_gate(difference[i], selected)
        }))
    }

    fn reduce(builder: &mut CircuitBuilder, bits: &[Node<Feed>]) -> Self {
        let mut remainder = Self::constant(builder, KoalaBear::ZERO);
        for bit in bits.iter().rev() {
            let shifted = from_fn(|i| if i == 0 { *bit } else { remainder.0[i - 1] });
            // PROOF: r < p implies 2r + bit < 2p.
            remainder = Self::reduce_once(builder, shifted);
        }
        remainder
    }

    fn add(self, builder: &mut CircuitBuilder, rhs: Self) -> Self {
        let mut carry = builder.get_const_zero();
        let mut sum = [builder.get_const_zero(); 32];
        for (i, out) in sum.iter_mut().take(31).enumerate() {
            (*out, carry) = ops::full_adder(builder, self.0[i], rhs.0[i], carry);
        }
        sum[31] = carry;
        Self::reduce_once(builder, sum)
    }

    fn mul(self, builder: &mut CircuitBuilder, rhs: Self) -> Self {
        let mut product = [builder.get_const_zero(); 62];
        for (shift, bit) in rhs.0.into_iter().enumerate() {
            let mut carry = builder.get_const_zero();
            for i in 0..31 {
                let partial = builder.add_and_gate(self.0[i], bit);
                (product[shift + i], carry) =
                    ops::full_adder(builder, product[shift + i], partial, carry);
            }
            // PROOF: earlier partial products use at most shift + 31 bits.
            product[shift + 31] = carry;
        }
        Self::reduce(builder, &product)
    }

    fn cube(self, builder: &mut CircuitBuilder) -> Self {
        let square = self.mul(builder, self);
        square.mul(builder, self)
    }
}

fn external(builder: &mut CircuitBuilder, state: &mut [Word; 16]) {
    for x in state.as_chunks_mut::<4>().0 {
        let t01 = x[0].add(builder, x[1]);
        let t23 = x[2].add(builder, x[3]);
        let sum = t01.add(builder, t23);
        let s1 = sum.add(builder, x[1]);
        let s3 = sum.add(builder, x[3]);
        let d0 = x[0].add(builder, x[0]);
        let d2 = x[2].add(builder, x[2]);
        *x = [
            s1.add(builder, t01),
            s1.add(builder, d2),
            s3.add(builder, t23),
            s3.add(builder, d0),
        ];
    }
    let sums: [_; 4] = from_fn(|i| {
        let a = state[i].add(builder, state[i + 4]);
        let b = state[i + 8].add(builder, state[i + 12]);
        a.add(builder, b)
    });
    for (i, word) in state.iter_mut().enumerate() {
        *word = word.add(builder, sums[i % 4]);
    }
}

fn full_rounds(builder: &mut CircuitBuilder, state: &mut [Word; 16], rounds: &[[KoalaBear; 16]]) {
    for constants in rounds {
        for (word, constant) in state.iter_mut().zip(constants) {
            let constant = Word::constant(builder, *constant);
            *word = word.add(builder, constant).cube(builder);
        }
        external(builder, state);
    }
}

/// `fn([u32; 16]) -> [u32; 16]`; inputs are reduced modulo p, outputs are canonical.
pub fn permute() -> Result<Circuit, BuilderError> {
    let mut builder = CircuitBuilder::new();
    let input: [[_; 32]; 16] = from_fn(|_| from_fn(|_| builder.add_input()));
    let mut state = input.map(|bits| Word::reduce(&mut builder, &bits));
    external(&mut builder, &mut state);
    full_rounds(
        &mut builder,
        &mut state,
        &KOALABEAR_POSEIDON2_RC_16_EXTERNAL_INITIAL,
    );

    let mut diagonal = [KoalaBear::ONE; 16];
    GenericPoseidon2LinearLayersKoalaBear::internal_linear_layer(&mut diagonal);
    let diagonal = diagonal.map(|value| value - KoalaBear::from_u32(16));
    for constant in KOALABEAR_POSEIDON2_RC_16_INTERNAL {
        let constant = Word::constant(&builder, constant);
        state[0] = state[0].add(&mut builder, constant).cube(&mut builder);
        let zero = Word::constant(&builder, KoalaBear::ZERO);
        let sum = state
            .into_iter()
            .fold(zero, |sum, word| sum.add(&mut builder, word));
        for (word, coefficient) in state.iter_mut().zip(diagonal) {
            let coefficient = Word::constant(&builder, coefficient);
            *word = word.mul(&mut builder, coefficient).add(&mut builder, sum);
        }
    }
    full_rounds(
        &mut builder,
        &mut state,
        &KOALABEAR_POSEIDON2_RC_16_EXTERNAL_FINAL,
    );
    for word in state {
        for bit in word.0 {
            let output = builder.add_id_gate(bit);
            builder.add_output(output);
        }
        // PROOF: the builder requires an actual gate for each output, including zero.
        let zero = builder.add_xor_gate(input[0][0], input[0][0]);
        builder.add_output(zero);
    }
    builder.build()
}

/// `fn(u32) -> u32`: field increment for full-block sponge padding.
pub fn increment() -> Result<Circuit, BuilderError> {
    let mut builder = CircuitBuilder::new();
    let input: [_; 32] = from_fn(|_| builder.add_input());
    let value = Word::reduce(&mut builder, &input);
    let one = Word::constant(&builder, KoalaBear::ONE);
    for bit in value.add(&mut builder, one).0 {
        let output = builder.add_id_gate(bit);
        builder.add_output(output);
    }
    let zero = builder.add_xor_gate(input[0], input[0]);
    builder.add_output(zero);
    builder.build()
}
