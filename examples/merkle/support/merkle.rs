use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::{KoalaBear as F, default_koalabear_poseidon2_16};
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};
use serde_json::{Value, json};

pub const MAX_HEIGHT: u32 = 3;
const LEAF: u32 = 0x504d_0101;
pub const NODE: u32 = 0x504d_0102;
pub fn hash(tag: u32, words: &[u32]) -> [u32; 8] {
    let domain = [tag, words.len() as u32, 0, 0, 0, 0, 0, 0];
    PaddingFreeSponge::<_, 16, 8, 8>::new(default_koalabear_poseidon2_16())
        .hash_iter(
            domain
                .into_iter()
                .chain(words.iter().copied())
                .map(F::from_u32),
        )
        .map(|word| word.as_canonical_u32())
}
pub fn circuit(height: u32) -> Value {
    let (private, children, mut operations, root) = if height == 0 {
        (
            8,
            vec![],
            vec![json!({"op":"poseidon2","tag":LEAF,"inputs":(9..17).collect::<Vec<_>>()})],
            17,
        )
    } else {
        (
            0,
            vec![circuit(height - 1)],
            vec![
                json!({"op":"verify","child":0}),
                json!({"op":"verify","child":0}),
                json!({"op":"poseidon2","tag":NODE,"inputs":(10..18).chain(19..27).collect::<Vec<_>>()}),
            ],
            27,
        )
    };
    operations.push(json!({"op":"constant","value":height}));
    let constraints = std::iter::once(json!({"op":"equal","left":0,"right":root+8}))
        .chain((0..8).map(|index| json!({"op":"equal","left":index+1,"right":root+index})))
        .collect::<Vec<_>>();
    json!({"format":proof_client_core::proof::FORMAT,"inputs":{"public":9,"private":private},"children":children,"operations":operations,"constraints":constraints})
}
pub fn leaf(index: u32) -> Value {
    let words = (index * 8..index * 8 + 8).collect::<Vec<_>>();
    let public = std::iter::once(0)
        .chain(hash(LEAF, &words))
        .collect::<Vec<_>>();
    json!({"public":public,"private":words,"proofs":[]})
}
pub fn parent(height: u32, left: Value, right: Value) -> Result<(Value, Value), serde_json::Error> {
    let left_values: Vec<u32> =
        serde_json::from_value(left.get("public").cloned().ok_or_else(|| {
            <serde_json::Error as serde::de::Error>::custom("missing left public values")
        })?)?;
    let right_values: Vec<u32> =
        serde_json::from_value(right.get("public").cloned().ok_or_else(|| {
            <serde_json::Error as serde::de::Error>::custom("missing right public values")
        })?)?;
    let words = left_values
        .into_iter()
        .skip(1)
        .chain(right_values.into_iter().skip(1))
        .collect::<Vec<_>>();
    let public = std::iter::once(height)
        .chain(hash(NODE, &words))
        .collect::<Vec<_>>();
    Ok((
        circuit(height),
        json!({"public":public,"private":[],"proofs":[left,right]}),
    ))
}
pub fn expected(height: u32) -> Vec<u32> {
    let mut level = (0..1 << height)
        .map(|index| hash(LEAF, &(index * 8..index * 8 + 8).collect::<Vec<_>>()))
        .collect::<Vec<_>>();
    while level.len() > 1 {
        level = level
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| hash(NODE, &pair.iter().flatten().copied().collect::<Vec<_>>()))
            .collect();
    }
    std::iter::once(height)
        .chain(level.into_iter().flatten())
        .collect()
}
