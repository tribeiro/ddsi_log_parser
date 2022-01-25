use regex::Captures;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{self, prelude::*, BufReader};

mod ddsi_log_regex;
mod ddsi_participant;
mod ddsi_topology;

pub trait DdsiLogConfig {
    fn get_filename(&self) -> &str;
    fn get_output(&self) -> &str;
}

pub fn run<T>(config: &T) -> Result<(), Box<dyn Error>>
where
    T: DdsiLogConfig,
{
    println!(
        "Processing '{}' and storing results in '{}'.",
        &config.get_filename(),
        &config.get_output(),
    );

    let summary = generate_summary(&config.get_filename());

    println!("{}", summary);

    Ok(())
}

fn generate_summary(filename: &str) -> String {
    let ddsi_log_regex = ddsi_log_regex::DdsiLogRegex::new();

    let file = File::open(filename).unwrap();
    let reader = BufReader::new(file);

    let mut ddsi_topology = ddsi_topology::DdsiTopology::new();

    for line in reader.lines() {
        if let Some(dds_log_type) = ddsi_log_regex.parse(&line.unwrap()) {
            ddsi_topology.update(dds_log_type);
        }
    }

    println!("Generating summary.");
    let summary = ddsi_topology.summarize();

    format!(
        "Summary:\n\
        \t- Found {} lines matching ddsi logs.\n\
        {}",
        ddsi_topology.len(),
        summary,
    )
}
