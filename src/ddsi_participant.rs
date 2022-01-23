use crate::ddsi_log_regex::DdsiLogType;
use log::debug;
use regex::Captures;
use std::collections::HashMap;
use std::{error::Error, fmt};

#[derive(Debug)]
struct WrongSystemId {
    participant_id: String,
    update_id: String,
}

impl Error for WrongSystemId {}

impl fmt::Display for WrongSystemId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "Input system id {} does not match expected id {}.",
            self.update_id, self.participant_id,
        )
    }
}

#[derive(Debug)]
pub struct DdsiParticipant {
    system_id: String,
    readers: HashMap<String, Qos>,
    writers: HashMap<String, Qos>,
    is_master: bool,
    master_id: String,
}

#[derive(Debug)]
pub struct Qos {
    topic: String,
    partition: String,
}

impl DdsiParticipant {
    pub fn new(system_id: &str) -> DdsiParticipant {
        DdsiParticipant {
            system_id: String::from(system_id),
            readers: HashMap::new(),
            writers: HashMap::new(),
            is_master: false,
            master_id: String::new(),
        }
    }

    /// Return a clone of the system id value.
    pub fn get_system_id(&self) -> String {
        self.system_id.clone()
    }

    /// Update information based on input ddsi log type.
    pub fn update(&mut self, ddsi_log_type: DdsiLogType) -> Result<(), Box<dyn Error>> {
        match ddsi_log_type {
            DdsiLogType::HandleParticipantsSelf(capture) => {
                debug!("HandleParticipantsSelf: {}", &capture["system_id"]);
                self.check_system_id(&capture["system_id"])
            }
            DdsiLogType::WriterQos(capture) => {
                debug!("WriterQos: {}", &capture["system_id"]);
                self.update_writer_qos(capture)
            }
            DdsiLogType::ReaderQos(capture) => {
                debug!("ReaderQos: {}", &capture["system_id"]);
                self.update_reader_qos(capture)
            }
            DdsiLogType::SedpSt0(capture) => {
                debug!("SedpSt0: {}", &capture["system_id"]);
                self.update_sedp_st0(capture)
            }
        }
    }

    fn check_system_id(&self, other_id: &str) -> Result<(), Box<dyn Error>> {
        if other_id != self.system_id {
            return Err(Box::new(WrongSystemId {
                participant_id: self.system_id.clone(),
                update_id: String::from(other_id),
            }));
        }
        Ok(())
    }

    fn update_writer_qos(&mut self, capture: Captures) -> Result<(), Box<dyn Error>> {
        if let Err(check) = self.check_system_id(&capture["system_id"]) {
            return Err(check);
        }
        self.writers.insert(
            String::from(&capture["rw_id"]),
            Qos {
                topic: String::from(&capture["topic"]),
                partition: String::from(&capture["partition"]),
            },
        );
        self.readers.insert(
            String::from(&capture["rw_id"]),
            Qos {
                topic: String::from(&capture["topic"]),
                partition: String::from(&capture["partition"]),
            },
        );
        Ok(())
    }

    fn update_reader_qos(&mut self, capture: Captures) -> Result<(), Box<dyn Error>> {
        if let Err(check) = self.check_system_id(&capture["system_id"]) {
            return Err(check);
        }
        self.readers.insert(
            String::from(&capture["rw_id"]),
            Qos {
                topic: String::from(&capture["topic"]),
                partition: String::from(&capture["partition"]),
            },
        );
        Ok(())
    }

    fn update_sedp_st0(&mut self, capture: Captures) -> Result<(), Box<dyn Error>> {
        if let Err(check) = self.check_system_id(&capture["system_id"]) {
            return Err(check);
        } else if &capture["rw"] == "writer" {
            self.writers.insert(
                String::from(&capture["rw_id"]),
                Qos {
                    topic: String::from(&capture["topic"]),
                    partition: String::from(&capture["partition"]),
                },
            );
        } else {
            self.readers.insert(
                String::from(&capture["rw_id"]),
                Qos {
                    topic: String::from(&capture["topic"]),
                    partition: String::from(&capture["partition"]),
                },
            );
        }
        Ok(())
    }
}
