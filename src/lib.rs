use indicatif::{ProgressBar, ProgressStyle};
use regex::Captures;
use std::collections::HashMap;
use std::error::Error;
use std::fs::{metadata, File};
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

    println!("Writing summary to {}", &config.get_output());

    let mut file = File::create(&config.get_output())?;
    file.write_all(summary.as_bytes())?;

    Ok(())
}

fn generate_summary(filename: &str) -> String {
    let ddsi_log_regex = ddsi_log_regex::DdsiLogRegex::new();

    let file = File::open(filename).unwrap();

    let n_lines = metadata(filename).unwrap().len();

    let reader = BufReader::new(file);

    let mut ddsi_topology = ddsi_topology::DdsiTopology::new();

    println!("Processing {} lines", n_lines);

    let bar = ProgressBar::new(n_lines);

    bar.set_style(
        ProgressStyle::default_bar()
            .template("[{elapsed}] {bar:40.cyan/blue} {eta} {msg}")
            .progress_chars("##-"),
    );

    let mut n_matcher = 0;

    for line in reader.lines() {
        let line_data = &line.unwrap();

        if let Some(dds_log_type) = ddsi_log_regex.parse(line_data) {
            ddsi_topology.update(dds_log_type);
            n_matcher += 1;
        }
        bar.inc(line_data.len() as u64);
    }
    bar.finish();

    println!("Generating summary.");
    let summary = ddsi_topology.summarize();

    println!("Saving ddsi_topology.");

    let serialized = serde_json::to_string(&ddsi_topology).unwrap();

    let mut file = File::create("ddsi_topology.json").unwrap();
    file.write_all(serialized.as_bytes()).unwrap();

    format!(
        "Summary:\n\
        \t- Found {} lines matching ddsi logs.\n\
        {}",
        n_matcher, summary,
    )
}
