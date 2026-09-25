use clap::Parser;
use proof_client::{
    app::{self, Cli, CliError, Execution},
    identity::parse_origin,
    stdio::{self, Event},
};
use std::io::{self, Write};

fn main() -> Result<(), CliError> {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => match error.kind() {
            clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion => {
                error.print()?;
                return Ok(());
            }
            kind => return Err(CliError::Arguments(kind)),
        },
    };
    match (cli.command, cli.origin) {
        (Some(command), None) => {
            let result = app::execute(command, |address| {
                emit(&mut io::stderr().lock(), &Event::Ready { address })
            })?;
            let mut output = io::stdout().lock();
            match result {
                Execution::Json(result) => emit(&mut output, &Event::Completed { result })?,
                Execution::Http { bytes, .. } => {
                    // PROOF: the user requested raw HTTP bytes from the authenticated exchange.
                    output.write_all(&bytes)?;
                    output.flush()?;
                }
            }
        }
        (None, Some(origin)) => {
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
