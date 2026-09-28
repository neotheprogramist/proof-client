use p3_recursion::builtin_config;

#[derive(thiserror::Error)]
pub enum Error {
    #[error("invalid or unsupported proof artifact")]
    Artifact,
    #[error("proof statement does not match the supplied circuit")]
    Statement,
    #[error("invalid or unsupported circuit, witness, or proof shape")]
    Shape,
    #[error("invalid JSON input")]
    Json(#[from] serde_json::Error),
    #[error("cannot construct the proof configuration: {0}")]
    Config(#[from] builtin_config::BuiltinConfigError),
    #[error("cannot obtain cryptographic randomness: {0}")]
    Random(#[from] rand::rngs::SysError),
    #[error("circuit construction failed: {0}")]
    Build(#[from] p3_circuit::CircuitBuilderError),
    #[error("invalid statement schema: {0}")]
    Schema(#[from] p3_circuit::StatementError),
    #[error("circuit execution failed")]
    Circuit(#[from] p3_circuit::CircuitError),
    #[error("proving or verification failed")]
    Proof(#[from] p3_circuit_prover::BatchStarkProverError),
    #[error("recursive verifier failed")]
    Recursion(#[from] p3_recursion::verifier::VerificationError),
    #[error("cannot create proving workers: {0}")]
    Pool(#[from] rayon::ThreadPoolBuildError),
}
impl std::fmt::Debug for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}
