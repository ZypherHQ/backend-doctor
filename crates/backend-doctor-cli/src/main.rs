use backend_doctor_cli::{run, Cli};
use clap::Parser;
use std::process::ExitCode;

fn main() -> ExitCode {
    let code = run(Cli::parse());
    ExitCode::from(code as u8)
}
