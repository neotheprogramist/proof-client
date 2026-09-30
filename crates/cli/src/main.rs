use clap::Parser;
use proof_client::{
    app::{self, Cli, CliError, Command, Format},
    identity::parse_origin,
    stdio::{self, Event},
};
use std::io::{self, Write};

fn main() -> Result<(), CliError> {
    proof_client::logging::init()?;
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => match error.kind() {
            clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                error.print()?;
                return Ok(());
            }
            _ => return Err(error.into()),
        },
    };
    match (cli.command, cli.origin, cli.format) {
        (Some(command), None, format) => {
            if format == Format::Raw && !matches!(command, Command::Attest(_)) {
                return Err(CliError::RawFormat);
            }
            let result = app::execute(command, &cli.storage, |_| Ok(()))?;
            let mut output = io::stdout().lock();
            match format {
                Format::Human => proof_client::report::human(&mut output, &result)?,
                Format::Json => emit(
                    &mut output,
                    &Event::Completed {
                        result: result.json(),
                    },
                )?,
                Format::Raw => {
                    let app::Execution::Attested { artifact, .. } = result else {
                        return Err(CliError::RawFormat);
                    };
                    // PROOF: --format raw explicitly requests the private response bytes.
                    output.write_all(artifact.response())?;
                }
            }
            output.flush()?;
        }
        (None, Some(origin), Format::Human) => {
            parse_origin(&origin)?;
            stdio::run(&mut io::stdin().lock(), &mut io::stdout().lock())?;
        }
        _ => return Err(CliError::Invocation),
    }
    Ok(())
}
fn emit(writer: &mut impl Write, value: &impl serde::Serialize) -> Result<(), CliError> {
    serde_json::to_writer(&mut *writer, value)?;
    writer.write_all(b"\n")?;
    Ok(())
}
