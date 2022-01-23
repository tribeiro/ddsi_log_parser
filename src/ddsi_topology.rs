use crate::ddsi_log_regex::DdsiLogType;
use crate::ddsi_participant::DdsiParticipant;
use std::collections::HashMap;
use std::error::Error;

#[derive(Debug)]
pub struct DdsiTopology {
    participants: HashMap<String, DdsiParticipant>,
}

impl DdsiTopology {
    pub fn new() -> DdsiTopology {
        DdsiTopology {
            participants: HashMap::new(),
        }
    }

    pub fn update(&mut self, dds_log_type: DdsiLogType) -> Result<(), Box<dyn Error>> {
        let system_id = dds_log_type.get_system_id();
        let participant = self
            .participants
            .entry(system_id)
            .or_insert(DdsiParticipant::new(&dds_log_type.get_system_id()));

        participant.update(dds_log_type)
    }

    pub fn len(&self) -> usize {
        self.participants.len()
    }

    pub fn get_participants_ids(&self) -> Vec<String> {
        self.participants.keys().cloned().collect()
    }

    pub fn summarize(&self) -> String {
        String::new()
    }
}
