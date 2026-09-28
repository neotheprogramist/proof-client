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
            clap::error::ErrorKind::MissingRequiredArgument => {
                return Err(CliError::MissingArguments(error));
            }
            kind => return Err(CliError::Arguments(kind)),
        },
    };
    match (cli.command, cli.origin, cli.format) {
        (Some(Command::Attest(args)), None, Format::Raw) => {
            let (artifact, _) = app::attest(args, &cli.storage)?;
            let mut output = io::stdout().lock();
            // PROOF: --format raw explicitly requests the private response bytes.
            output.write_all(artifact.response())?;
            output.flush()?;
        }
        (Some(_), None, Format::Raw) => return Err(CliError::RawFormat),
        (Some(command), None, Format::Human) => {
            let result = app::execute(command, &cli.storage, |_| Ok(()))?;
            let mut output = io::stdout().lock();
            proof_client::report::human(&mut output, &result)?;
            output.flush()?;
        }
        (Some(command), None, Format::Json) => {
            let result = app::execute(command, &cli.storage, |_| Ok(()))?;
            emit(
                &mut io::stdout().lock(),
                &Event::Completed {
                    result: result.json(),
                },
            )?;
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
    writer.flush()?;
    Ok(())
}
