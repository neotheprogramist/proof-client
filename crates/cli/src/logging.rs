pub fn init() -> Result<(), tracing_subscriber::util::TryInitError> {
    use tracing_subscriber::{filter::Targets, prelude::*};
    tracing_subscriber::registry()
        .with(Targets::new().with_target("proof_client", tracing::Level::INFO))
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stderr))
        .try_init()
}
