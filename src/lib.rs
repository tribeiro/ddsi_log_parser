use regex::Captures;
use std::collections::HashMap;
use std::error::Error;
use std::fs;

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

    let contents = fs::read_to_string(config.get_filename())?;

    let summary = generate_summary(&contents);

    println!("{}", summary);

    Ok(())
}

fn generate_summary(contents: &str) -> String {
    let ddsi_log_regex = ddsi_log_regex::DdsiLogRegex::new();

    println!("Preprocessing {} lines.", contents.len());
    let matches: Vec<&str> = contents
        .lines()
        .filter(|line| ddsi_log_regex.is_match(&line))
        .collect();

    let n_matches = matches.len();
    let mut ddsi_topology = ddsi_topology::DdsiTopology::new();

    println!("Processing {} lines.", n_matches);

    for line in matches {
        let dds_log_type = ddsi_log_regex.parse(line).unwrap();
        ddsi_topology.update(dds_log_type);
    }

    println!("Generating summary.");
    let summary = ddsi_topology.summarize();

    format!(
        "Summary:\n\
        \t- Found {} lines matching ddsi logs.\n\
        {}",
        n_matches, summary,
    )
}
