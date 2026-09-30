use mpz_circuits_core::Circuit;
use std::{
    fs::write,
    path::{Path, PathBuf},
};

#[derive(Debug, thiserror::Error)]
enum BuildError {
    #[error("building circuit: {0}")]
    Circuit(#[from] mpz_circuits_core::BuilderError),
    #[error("encoding circuit: {0}")]
    Encode(#[from] bincode::Error),
    #[error("writing generated circuit: {0}")]
    Write(#[from] std::io::Error),
}

fn main() -> Result<(), BuildError> {
    println!("cargo:rerun-if-changed=../circuits-core/bristol");

    let manifest_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
    let circuits_dir = PathBuf::from(manifest_dir).join("../circuits-core/bristol");
    let output = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    build_aes(&circuits_dir, &output);
    build_sha2(&circuits_dir, &output);
    build_blake3(&output);
    build_keccak(&circuits_dir, &output);
    #[cfg(feature = "poseidon2-koalabear")]
    {
        use mpz_circuits_core::circuits::poseidon2_koalabear;
        for (name, circuit) in [
            ("poseidon2_koalabear", poseidon2_koalabear::permute()?),
            ("koalabear_increment", poseidon2_koalabear::increment()?),
        ] {
            write(output.join(format!("{name}.bin")), bincode::serialize(&circuit)?)?;
        }
    }
    Ok(())
}

fn build_aes(circuits_dir: &Path, output: &Path) {
    let path = circuits_dir.join("aes_128_reverse.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write(output.join("aes_128.bin"), bytes).unwrap();

    let path = circuits_dir.join("aes_128_key_schedule.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write(output.join("aes_128_ks.bin"), bytes).unwrap();

    let path = circuits_dir.join("aes_128_post_key_schedule.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write(output.join("aes_128_post_ks.bin"), bytes).unwrap();
}

fn build_sha2(circuits_dir: &Path, output: &Path) {
    let path = circuits_dir.join("sha256_reverse.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write(output.join("sha256.bin"), bytes).unwrap();
}

fn build_blake3(output: &Path) {
    let circ = mpz_circuits_core::circuits::blake3::compress();

    let bytes = bincode::serialize(&circ).unwrap();
    write(output.join("blake3.bin"), bytes).unwrap();
}

fn build_keccak(circuits_dir: &Path, output: &Path) {
    let path = circuits_dir.join("keccak_f.txt");
    let circ = Circuit::parse(path.as_path().to_str().unwrap()).unwrap();

    let bytes = bincode::serialize(&circ).unwrap();
    write(output.join("keccak_f.bin"), bytes).unwrap();
}
