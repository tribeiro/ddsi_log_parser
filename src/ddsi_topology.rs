use crate::ddsi_participant::DdsiParticipant;
use std::collections::HashMap;

pub struct DdsiTopology {
    participants: HashMap<String, DdsiParticipant>,
}
