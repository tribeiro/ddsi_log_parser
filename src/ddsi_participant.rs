use crate::ddsi_log_regex::DdsiLogType;
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

pub struct DdsiParticipant {
    system_id: String,
    readers: HashMap<String, Qos>,
    writers: HashMap<String, Qos>,
    is_master: bool,
    master_id: String,
}

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

    pub fn update(&mut self, ddsi_log_type: DdsiLogType) -> Result<(), Box<dyn Error>> {
        match ddsi_log_type {
            DdsiLogType::HandleParticipantsSelf(capture) => {
                println!("HandleParticipantsSelf: {}", &capture["system_id"]);
                if &capture["system_id"] != self.system_id {
                    return Err(Box::new(WrongSystemId {
                        participant_id: self.system_id.clone(),
                        update_id: String::from(&capture["system_id"]),
                    }));
                }
                Ok(())
            }
            DdsiLogType::RwQos(capture) => {
                println!("RwQos: {}", &capture["system_id"]);
                if &capture["system_id"] != self.system_id {
                    return Err(Box::new(WrongSystemId {
                        participant_id: self.system_id.clone(),
                        update_id: String::from(&capture["system_id"]),
                    }));
                } else if &capture["rw"] == "WRITER" {
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
            DdsiLogType::SedpSt0(capture) => {
                println!("SedpSt0: {}", &capture["system_id"]);
                if &capture["system_id"] != self.system_id {
                    return Err(Box::new(WrongSystemId {
                        participant_id: self.system_id.clone(),
                        update_id: String::from(&capture["system_id"]),
                    }));
                } else if &capture["rw"] == "WRITER" {
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
    }
}
