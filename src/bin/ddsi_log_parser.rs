use clap::Parser;
use log;
use std::process;

/// Process ddsi log file and generate summary.
#[derive(Parser)]
struct Cli {
    /// ddsi log file to process.
    #[clap(short = 'f', long = "filename")]
    filename: String,

    /// Name of the output file.
    #[clap(short = 'o', long = "output")]
    output: String,
}

impl ddsi_log_parser::DdsiLogConfig for Cli {
    fn get_filename(&self) -> &str {
        &self.filename
    }

    fn get_output(&self) -> &str {
        &self.output
    }
}

fn main() {
    let args = Cli::parse();

    if let Err(e) = ddsi_log_parser::run(&args) {
        eprintln!("Application error: {:?}", e);
        process::exit(1);
    }
}
