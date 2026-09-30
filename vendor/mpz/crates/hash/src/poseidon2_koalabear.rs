//! poseidon2-koalabear-16-pad10-v1 over authenticated byte references.

use mpz_circuits::{KOALABEAR_INCREMENT, POSEIDON2_KOALABEAR};
use mpz_vm_core::{
    Call, CallError, CallableExt, Vm, VmError,
    memory::{
        Array, FromRaw, MemoryExt, Slice, ToRaw, Vector, ViewExt,
        binary::{Binary, U8, U32},
    },
};

/// Errors at the authenticated byte-hash boundary.
#[derive(Debug, thiserror::Error)]
pub enum Poseidon2Error {
    /// VM operation failed.
    #[error("KoalaBear VM: {0}")]
    Vm(#[from] VmError),
    /// Generated circuit failed to decode.
    #[error("KoalaBear circuit: {0}")]
    Circuit(#[source] &'static bincode::ErrorKind),
    /// Circuit arguments have an incorrect length.
    #[error("KoalaBear call: {0}")]
    Call(#[from] CallError),
}

/// Partition-independent byte hash; the caller owns the input references.
#[derive(Default)]
pub struct Poseidon2KoalaBear {
    inputs: Vec<Slice>,
}

fn bytes(mut input: Slice) -> impl Iterator<Item = Slice> {
    std::iter::from_fn(move || {
        if input.len() == 0 {
            return None;
        }
        // PROOF: input references and every remainder contain whole bytes.
        let (byte, rest) = input.split_at(8);
        input = rest;
        Some(byte)
    })
}

impl Poseidon2KoalaBear {
    /// Appends bytes without introducing a partition delimiter.
    pub fn update(&mut self, input: &Vector<U8>) {
        self.inputs.push(input.to_raw());
    }

    /// Finalizes the frozen byte encoding and padded sponge.
    pub fn finalize(self, vm: &mut dyn Vm<Binary>) -> Result<Array<U8, 32>, Poseidon2Error> {
        let circuit = match &*POSEIDON2_KOALABEAR {
            Ok(circuit) => circuit,
            Err(error) => return Err(Poseidon2Error::Circuit(error)),
        };
        let increment = match &*KOALABEAR_INCREMENT {
            Ok(circuit) => circuit,
            Err(error) => return Err(Poseidon2Error::Circuit(error)),
        };
        let domain = b"tlsn/poseidon2/koalabear/16/pad10/v1";
        let prefix = vm.alloc_vec::<U8>(domain.len())?;
        vm.mark_public(prefix)?;
        vm.assign(prefix, domain.to_vec())?;
        vm.commit(prefix)?;
        let zeros: Array<U32, 16> = vm.alloc()?;
        vm.mark_public(zeros)?;
        vm.assign(zeros, [0u32; 16])?;
        vm.commit(zeros)?;
        let one: U32 = vm.alloc()?;
        vm.mark_public(one)?;
        vm.assign(one, 1u32)?;
        vm.commit(one)?;
        // PROOF: typed U32 storage contains at least eight bits.
        let zero_byte = zeros.to_raw().split_at(8).0;
        let marker = one.to_raw().split_at(8).0;
        let mut input = bytes(prefix.to_raw())
            .chain(self.inputs.into_iter().flat_map(bytes))
            .chain([marker])
            .peekable();
        let mut state = zeros;
        loop {
            let mut call = Call::builder(circuit.clone());
            let mut used = 0;
            while used < 8 && input.peek().is_some() {
                for _ in 0..3 {
                    // Zero-fill the final three-byte group.
                    let byte = match input.next() {
                        Some(byte) => byte,
                        None => zero_byte,
                    };
                    call = call.arg(byte);
                }
                call = call.arg(zero_byte);
                used += 1;
            }
            let last = input.peek().is_none();
            // PROOF: the state is exactly sixteen U32 words.
            let capacity = state.to_raw().split_at(8 * 32).1;
            if used < 8 {
                // PROOF: used < 8 bounds the zero suffix within the sixteen-word buffer.
                call = call
                    .arg(one)
                    .arg(zeros.to_raw().split_at((7 - used) * 32).0)
                    .arg(capacity);
            } else if last {
                let (first, rest) = capacity.split_at(32);
                let first: U32 = vm.call(Call::builder(increment.clone()).arg(first).build()?)?;
                call = call.arg(first).arg(rest);
            } else {
                call = call.arg(capacity);
            }
            state = vm.call(call.build()?)?;
            if last {
                // PROOF: the first eight U32 words occupy exactly 32 bytes in Binary's LSB0 encoding.
                return Ok(<Array<U8, 32> as FromRaw<Binary>>::from_raw(
                    state.to_raw().split_at(8 * 32).0,
                ));
            }
        }
    }
}
