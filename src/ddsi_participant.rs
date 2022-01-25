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
    hostname: String,
    readers: HashMap<String, Qos>,
    writers: HashMap<String, Qos>,
    is_master: bool,
    master_id: String,
}

#[derive(Debug)]
pub struct Qos {
    topic: String,
    partition: String,
    created: Vec<f64>,
    deleted: Vec<f64>,
}

impl DdsiParticipant {
    pub fn new(system_id: &str, own_ip: &str) -> DdsiParticipant {
        DdsiParticipant {
            system_id: String::from(system_id),
            hostname: String::from(own_ip),
            readers: HashMap::new(),
            writers: HashMap::new(),
            is_master: false,
            master_id: String::new(),
        }
    }

    /// Return the system id value.
    pub fn get_system_id(&self) -> &String {
        &self.system_id
    }

    /// Return hostname.
    pub fn get_hostname(&self) -> &String {
        &self.hostname
    }

    /// Return a vector with all the readers id.
    pub fn get_readers_id(&self) -> Vec<String> {
        self.readers.keys().cloned().collect()
    }

    /// Return a vector with all the writers id.
    pub fn get_writers_id(&self) -> Vec<String> {
        self.writers.keys().cloned().collect()
    }

    /// Return reader QoS.
    pub fn get_reader_qos(&self, reader_id: &String) -> Option<&Qos> {
        self.readers.get(reader_id)
    }

    /// Return writer QoS.
    pub fn get_writer_qos(&self, writer_id: &String) -> Option<&Qos> {
        self.writers.get(writer_id)
    }

    /// Update information based on input ddsi log type.
    pub fn update(&mut self, ddsi_log_type: DdsiLogType) -> Result<(), Box<dyn Error>> {
        match ddsi_log_type {
            DdsiLogType::WriterQos(capture) => {
                debug!("WriterQos: {}", &capture["system_id"]);
                self.update_writer_qos(capture)
            }
            DdsiLogType::ReaderQos(capture) => {
                debug!("ReaderQos: {}", &capture["system_id"]);
                self.update_reader_qos(capture)
            }
            DdsiLogType::WriterSedpSt0(capture) => {
                debug!("WriterSedpSt0: {}", &capture["system_id"]);
                self.update_writer_sedp_st0(capture)
            }
            DdsiLogType::ReaderSedpSt0(capture) => {
                debug!("ReaderSedpSt0: {}", &capture["system_id"]);
                self.update_reader_sedp_st0(capture)
            }
            DdsiLogType::WriterSedpSt3(capture) => {
                debug!("WriterSedpSt3: {}", &capture["system_id"]);
                self.update_writer_sedp_st3(capture)
            }
            DdsiLogType::ReaderSedpSt3(capture) => {
                debug!("ReaderSedpSt3: {}", &capture["system_id"]);
                self.update_reader_sedp_st3(capture)
            }
            DdsiLogType::OwnIp(_) => Ok(()),
            DdsiLogType::HandleParticipantsSelf(capture) => {
                debug!("HandleParticipantsSelf: {}", &capture["system_id"]);
                if let Err(check) = self.check_system_id(&capture["system_id"]) {
                    return Err(check);
                } else {
                    self.system_id = String::from(&capture["system_id"]);
                    Ok(())
                }
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

        let rw_id = String::from(&capture["rw_id"]);

        let qos = self.writers.entry(rw_id).or_insert(Qos {
            topic: String::from(&capture["topic"]),
            partition: String::from(&capture["partition"]),
            created: vec![],
            deleted: vec![],
        });
        qos.created.push(capture["timestamp"].parse().unwrap());
        Ok(())
    }

    fn update_reader_qos(&mut self, capture: Captures) -> Result<(), Box<dyn Error>> {
        if let Err(check) = self.check_system_id(&capture["system_id"]) {
            return Err(check);
        }
        let rw_id = String::from(&capture["rw_id"]);

        let qos = self.readers.entry(rw_id).or_insert(Qos {
            topic: String::from(&capture["topic"]),
            partition: String::from(&capture["partition"]),
            created: vec![],
            deleted: vec![],
        });
        qos.created.push(capture["timestamp"].parse().unwrap());
        Ok(())
    }

    fn update_writer_sedp_st0(&mut self, capture: Captures) -> Result<(), Box<dyn Error>> {
        if let Err(check) = self.check_system_id(&capture["system_id"]) {
            return Err(check);
        }
        self.hostname = String::from(&capture["hostname"]);
        self.update_writer_qos(capture)
    }

    fn update_reader_sedp_st0(&mut self, capture: Captures) -> Result<(), Box<dyn Error>> {
        if let Err(check) = self.check_system_id(&capture["system_id"]) {
            return Err(check);
        }
        self.hostname = String::from(&capture["hostname"]);
        self.update_reader_qos(capture)
    }

    fn update_writer_sedp_st3(&mut self, capture: Captures) -> Result<(), Box<dyn Error>> {
        if let Err(check) = self.check_system_id(&capture["system_id"]) {
            return Err(check);
        } else {
            self.writers
                .entry(String::from(&capture["rw_id"]))
                .and_modify(|writer| writer.deleted.push(capture["timestamp"].parse().unwrap()));
        }
        Ok(())
    }

    fn update_reader_sedp_st3(&mut self, capture: Captures) -> Result<(), Box<dyn Error>> {
        if let Err(check) = self.check_system_id(&capture["system_id"]) {
            return Err(check);
        } else {
            self.readers
                .entry(String::from(&capture["rw_id"]))
                .and_modify(|writer| writer.deleted.push(capture["timestamp"].parse().unwrap()));
        }
        Ok(())
    }
}
