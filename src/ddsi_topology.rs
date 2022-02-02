use crate::ddsi_log_regex::DdsiLogType;
use crate::ddsi_participant::DdsiParticipant;
use serde::ser::{Serialize, SerializeStruct, Serializer};
use std::collections::HashMap;
use std::error::Error;

#[derive(Debug)]
pub struct DdsiTopology {
    participants: HashMap<String, DdsiParticipant>,
    own_ip: String,
}

impl DdsiTopology {
    pub fn new() -> DdsiTopology {
        DdsiTopology {
            participants: HashMap::new(),
            own_ip: String::from("unkwnown"),
        }
    }

    pub fn update(&mut self, dds_log_type: DdsiLogType) -> Result<(), Box<dyn Error>> {
        let system_id = dds_log_type.get_system_id();

        if let DdsiLogType::OwnIp(capture) = dds_log_type {
            self.own_ip = String::from(&capture["hostname"]);
            Ok(())
        } else {
            let participant = self
                .participants
                .entry(system_id)
                .or_insert(DdsiParticipant::new(
                    &dds_log_type.get_system_id(),
                    &self.own_ip,
                ));

            participant.update(dds_log_type)
        }
    }

    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn get_participants_ids(&self) -> Vec<String> {
        self.participants.keys().cloned().collect()
    }

    pub fn summarize(&self) -> String {
        let mut summary = format!(
            "\t- Found {} participants: {:?}.\n",
            self.len(),
            self.get_participants_ids()
        );

        for participant_id in self.get_participants_ids() {
            let participant = self.participants.get(&participant_id).unwrap();

            summary.push_str(&format!(
                "\t- Participant {}@{}:\n",
                participant_id,
                participant.get_hostname()
            ));

            let readers_id = participant.get_readers_id();

            summary.push_str(&format!("\t\t- Readers {}:\n", readers_id.len()));

            for id in readers_id {
                let qos = participant.get_reader_qos(&id).unwrap();
                summary.push_str(&format!("\t\t\t- {}: {:?}\n", id, qos));
            }

            let writers_id = participant.get_writers_id();

            summary.push_str(&format!("\t\t- Writers {}:\n", writers_id.len()));

            for id in writers_id {
                let qos = participant.get_writer_qos(&id).unwrap();
                summary.push_str(&format!("\t\t\t- {}: {:?}\n", id, qos));
            }
        }
        summary
    }
}

impl Serialize for DdsiTopology {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        // 3 is the number of fields in the struct.
        let mut state = serializer.serialize_struct("DdsiTopology", 2)?;
        state.serialize_field("participants", &self.participants)?;
        state.serialize_field("own_ip", &self.own_ip)?;
        state.end()
    }
}
