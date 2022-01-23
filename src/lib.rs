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

    let matches: Vec<&str> = contents
        .lines()
        .filter(|line| ddsi_log_regex.is_match(&line))
        .collect();

    // let system_ids: HashMap<String, &Captures> = matches
    //     .iter()
    //     .map(|line| {
    //         let captured = ddsi_log_regex.parse(line).unwrap().get_capture();
    //         (captured["system_id"].to_string(), captured)
    //     })
    //     .collect();

    let n_matches = matches.len();
    let mut system_ids: HashMap<String, usize> = HashMap::new();

    for line in matches {
        let captured = ddsi_log_regex.parse(line).unwrap();
        let system_id = captured.get_capture()["system_id"].to_string();
        let count = system_ids.entry(system_id).or_insert(0);
        *count += 1;
    }

    format!(
        "Summary:\n\t- Found {} lines matching ddsi logs.\n\n{:?}",
        n_matches, system_ids,
    )
}
