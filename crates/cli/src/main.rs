use clap::Parser;
use proof_client::{
    app::{self, Cli, CliError},
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
            let mut output = io::stdout().lock();
            let result = app::execute(command, |address| {
                emit(&mut output, &Event::Ready { address })
            })?;
            emit(&mut output, &Event::Completed { result })?;
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
