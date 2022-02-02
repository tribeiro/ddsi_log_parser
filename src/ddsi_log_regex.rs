use regex::{Captures, Regex, RegexSet};

/// Provide a set of regular expressions and methods for parsing ddsi log
/// entries.
pub struct DdsiLogRegex {
    regex_set: RegexSet,
    regex: Vec<Regex>,
}

pub enum DdsiLogType<'a> {
    HandleParticipantsSelf(Captures<'a>),
    WriterQos(Captures<'a>),
    ReaderQos(Captures<'a>),
    WriterSedpSt0(Captures<'a>),
    ReaderSedpSt0(Captures<'a>),
    OwnIp(Captures<'a>),
    WriterSedpSt3(Captures<'a>),
    ReaderSedpSt3(Captures<'a>),
}

impl<'a> DdsiLogType<'a> {
    pub fn get_capture(&self) -> &Captures<'a> {
        match self {
            DdsiLogType::HandleParticipantsSelf(capture) => capture,
            DdsiLogType::WriterQos(capture) => capture,
            DdsiLogType::ReaderQos(capture) => capture,
            DdsiLogType::WriterSedpSt0(capture) => capture,
            DdsiLogType::ReaderSedpSt0(capture) => capture,
            DdsiLogType::OwnIp(capture) => capture,
            DdsiLogType::WriterSedpSt3(capture) => capture,
            DdsiLogType::ReaderSedpSt3(capture) => capture,
        }
    }
    pub fn get_system_id(&self) -> String {
        match self {
            DdsiLogType::HandleParticipantsSelf(capture) => String::from(&capture["system_id"]),
            DdsiLogType::ReaderQos(capture) => String::from(&capture["system_id"]),
            DdsiLogType::WriterQos(capture) => String::from(&capture["system_id"]),
            DdsiLogType::WriterSedpSt0(capture) => String::from(&capture["system_id"]),
            DdsiLogType::ReaderSedpSt0(capture) => String::from(&capture["system_id"]),
            DdsiLogType::OwnIp(_) => String::from("ownip"),
            DdsiLogType::WriterSedpSt3(capture) => String::from(&capture["system_id"]),
            DdsiLogType::ReaderSedpSt3(capture) => String::from(&capture["system_id"]),
        }
    }
}

const HEADER_REGEX: &str = r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})\+(?P<timezone>\d{4}) (?P<timestamp>[0-9]*\.[0-9]*)/";
const WRITER_QOS_REGEX: &str = r"QOS=\{topic=(?P<topic>[a-zA-Z0-9_]*),type=(?P<type>[a-zA-Z0-9_:]*),presentation=(?P<presentation>[a-zA-Z0-9_:]*),partition=\{(?P<partition>.*)\},durability=(?P<qos_durability>[a-zA-Z0-9_:]*),durability_service=(?P<durability_service>[a-zA-Z0-9_:\{\}\.\-]*),deadline=(?P<deadline>[a-zA-Z0-9\.]*),latency_budget=(?P<latency_budget>[a-zA-Z0-9\.]*),liveliness=(?P<liveliness>[a-zA-Z0-9_:\.]*),reliability=(?P<qos_reliability>[a-zA-Z0-9_:\.]*),destination_order=(?P<destination_order>[a-zA-Z0-9_:]*),history=(?P<history>[a-zA-Z0-9_:\-]*),resource_limits=(?P<resource_limits>[a-zA-Z0-9_:\-]*),transport_priority=(?P<transport_priority>[a-zA-Z0-9_:]*),lifespan=(?P<lifespan>[a-zA-Z0-9_:\.]*),ownership=(?P<ownership>[a-zA-Z0-9_:]*),ownership_strength=(?P<ownership_strength>[a-zA-Z0-9_:]*),writer_data_lifecycle=\{(?P<writer_data_lifecycle>[a-zA-Z0-9_:\.,]*)\},relaxed_qos_matching=(?P<relaxed_qos_matching>[a-zA-Z0-9_:]*),synchronous_endpoint=(?P<synchronous_endpoint>[a-zA-Z0-9_:]*)\}";
const READER_QOS_REGEX: &str = r"QOS=\{topic=(?P<topic>[a-zA-Z0-9_]*),type=(?P<type>[a-zA-Z0-9_:]*),presentation=(?P<presentation>[a-zA-Z0-9_:]*),partition=\{(?P<partition>.*)\},durability=(?P<qos_durability>[a-zA-Z0-9_:]*)(,durability_service=)?(?P<durability_service>[a-zA-Z0-9_:\{\}\.\-]*)?,deadline=(?P<deadline>[a-zA-Z0-9\.]*),latency_budget=(?P<latency_budget>[a-zA-Z0-9\.]*),liveliness=(?P<liveliness>[a-zA-Z0-9_:\.]*),reliability=(?P<qos_reliability>[a-zA-Z0-9_:\.]*),destination_order=(?P<destination_order>[a-zA-Z0-9_:]*),history=(?P<history>[a-zA-Z0-9_:\-]*),resource_limits=(?P<resource_limits>[a-zA-Z0-9_:\-]*),transport_priority=(?P<transport_priority>[a-zA-Z0-9_:]*)(,lifespan=)?(?P<lifespan>[a-zA-Z0-9_:\.]*)?,ownership=(?P<ownership>[a-zA-Z0-9_:]*),time_based_filter=(?P<time_based_filter>[0-9\.]*),reader_data_lifecycle=(?P<reader_data_lifecycle>[0-9_:\.]*),relaxed_qos_matching=(?P<relaxed_qos_matching>[0-9]*),reader_lifespan=\{(?P<reader_lifespan>[0-9\.,])*\},subscription_keys=\{(?P<subscription_keys>[0-9\{\},]*)\},share=\{(?P<share>[0-9\{\},]*)\},synchronous_endpoint=(?P<synchronous_endpoint>[a-zA-Z0-9_:]*)\}";
const SYSTEM_ID_REGEX: &str = r"(?P<system_id>[a-zA-Z0-9]*:[a-zA-Z0-9]*:[a-zA-Z0-9]*)";
const RW_ID_REGEX: &str = r"(?P<rw_id>[a-zA-Z0-9]*)";
const RELIABILITY_REGEX: &str = r"(?P<reliability>reliable|best-effort)";
const DURABILITY_REGEX: &str = r"(?P<durability>transient|volatile)";
const RW_REGEX: &str = r"(?P<rw>reader|writer)";
const SUBNET_REGEX: &str = r"(?P<subnet>[0-9\.]*)";
const SUBNET_PORT_REGEX: &str = r"(?P<subnet_port>[0-9]*)";
const HOSTNAME_REGEX: &str = r"(?P<hostname>[0-9\.]*)";
const HOSTNAME_PORT_REGEX: &str = r"(?P<hostname_port>[0-9]*)";

impl DdsiLogRegex {
    /// Create a new instance of DdsiLogRegex with the regular expressions
    /// needed to process ddsi log messages.
    pub fn new() -> DdsiLogRegex {
        let regex_set = RegexSet::new(&[
            [
                HEADER_REGEX,
                r"      main: handleParticipantsSelf: found ",
                SYSTEM_ID_REGEX,
                r" \(self\)",
            ]
            .join(r""),
            [
                HEADER_REGEX,
                r"(\s*)(?P<thread>[a-zA-Z0-9_\(\)]*): (?P<rw>[a-zA-Z0-9_]*) ",
                SYSTEM_ID_REGEX,
                r":",
                RW_ID_REGEX,
                r"(\s*)",
                WRITER_QOS_REGEX,
            ]
            .join(r""),
            [
                HEADER_REGEX,
                r"(\s*)(?P<thread>[a-zA-Z0-9_\(\)]*): (?P<rw>[a-zA-Z0-9_]*) ",
                SYSTEM_ID_REGEX,
                r":",
                RW_ID_REGEX,
                r"(\s*)",
                READER_QOS_REGEX,
            ]
            .join(r""),
            [
                HEADER_REGEX,
                r"dq.builtin: SEDP ST0 ",
                SYSTEM_ID_REGEX,
                r":",
                RW_ID_REGEX,
                r" ",
                RELIABILITY_REGEX,
                r" ",
                DURABILITY_REGEX,
                r" ",
                RW_REGEX,
                r": ",
                r"(?P<discard>.*) p\(open\) NEW \(as ",
                SUBNET_REGEX,
                r":",
                SUBNET_PORT_REGEX,
                r" ",
                HOSTNAME_REGEX,
                r":",
                HOSTNAME_PORT_REGEX,
                r"\) ",
                WRITER_QOS_REGEX,
            ]
            .join(r""),
            [
                HEADER_REGEX,
                r"dq.builtin: SEDP ST0 ",
                SYSTEM_ID_REGEX,
                r":",
                RW_ID_REGEX,
                r" ",
                RELIABILITY_REGEX,
                r" ",
                DURABILITY_REGEX,
                r" ",
                RW_REGEX,
                r": ",
                r"(?P<discard>.*) p\(open\) NEW \(as ",
                SUBNET_REGEX,
                r":",
                SUBNET_PORT_REGEX,
                r" ",
                HOSTNAME_REGEX,
                r":",
                HOSTNAME_PORT_REGEX,
                r"\) ",
                READER_QOS_REGEX,
            ]
            .join(r""),
            [HEADER_REGEX, r"      main: ownip: ", HOSTNAME_REGEX].join(r""),
            [
                HEADER_REGEX,
                r"dq.builtin: SEDP ST3 ",
                SYSTEM_ID_REGEX,
                r":",
                RW_ID_REGEX,
                "delete_proxy_writer",
            ]
            .join(r""),
            [
                HEADER_REGEX,
                r"dq.builtin: SEDP ST3 ",
                SYSTEM_ID_REGEX,
                r":",
                RW_ID_REGEX,
                "delete_proxy_reader",
            ]
            .join(r""),
        ])
        .unwrap();
        let regex = regex_set
            .patterns()
            .into_iter()
            .map(|pattern| Regex::new(pattern).unwrap())
            .collect();
        DdsiLogRegex { regex_set, regex }
    }

    /// Parse an input string using the collection of regular expressions for
    /// ddsi logs.
    ///
    /// # Arguments
    ///
    /// * `text` - A text to parse.
    ///
    pub fn parse<'a>(&self, text: &'a str) -> Option<DdsiLogType<'a>> {
        if let Some(match_index) = self.get_match_index(text) {
            let capture = self.regex[match_index].captures(text).unwrap();

            match match_index {
                0 => Some(DdsiLogType::HandleParticipantsSelf(capture)),
                1 => Some(DdsiLogType::WriterQos(capture)),
                2 => Some(DdsiLogType::ReaderQos(capture)),
                3 => Some(DdsiLogType::WriterSedpSt0(capture)),
                4 => Some(DdsiLogType::ReaderSedpSt0(capture)),
                5 => Some(DdsiLogType::OwnIp(capture)),
                6 => Some(DdsiLogType::WriterSedpSt3(capture)),
                7 => Some(DdsiLogType::ReaderSedpSt3(capture)),
                _ => None,
            }
        } else {
            None
        }
    }
    /// Check if input text is a valid ddsi log entry.
    pub fn is_match(&self, text: &str) -> bool {
        self.regex_set.is_match(text)
    }

    /// Return the index of the regex expression that matches the input text.
    fn get_match_index(&self, text: &str) -> Option<usize> {
        self.regex_set.matches(text).into_iter().next()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dds_log_regex_handle_participants_self() {
        let dds_log_regex = DdsiLogRegex::new();
        let handle_participants_self_sample =
            "2021-12-07T22:19:48+0000 1638915588.796443/      main: handleParticipantsSelf: found 428f812:7b:1 (self)";

        let matches = dds_log_regex
            .regex_set
            .matches(handle_participants_self_sample);

        let capture = dds_log_regex.regex[0]
            .captures(handle_participants_self_sample)
            .unwrap();

        assert!(matches.matched(0));
        assert_eq!(&capture["year"], "2021");
        assert_eq!(&capture["month"], "12");
        assert_eq!(&capture["day"], "07");
        assert_eq!(&capture["hour"], "22");
        assert_eq!(&capture["min"], "19");
        assert_eq!(&capture["sec"], "48");
        assert_eq!(&capture["timezone"], "0000");
        assert_eq!(&capture["timestamp"], "1638915588.796443");
        assert_eq!(&capture["system_id"], "428f812:7b:1");
    }

    #[test]
    fn dds_log_regex_writer_qos() {
        let dds_log_regex = DdsiLogRegex::new();
        let write_qos_sample = "2021-12-07T22:19:48+0000 1638915588.898675/      main: WRITER 428f812:7b:1:2302 QOS={topic=d_sampleChain,type=durabilityModule2::d_sampleChain_s,presentation=1:0:0,partition={durabilityPartition},durability=0,durability_service=0.000000000:{0:1}:{-1:-1:-1},deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:0.000000000,reliability=1:1.000000000,destination_order=0,history=1:1,resource_limits=1:-1:-1,transport_priority=0,lifespan=2147483647.999999999,ownership=0,ownership_strength=0,writer_data_lifecycle={1,2147483647.999999999,2147483647.999999999},relaxed_qos_matching=0,synchronous_endpoint=0}";

        let matches = dds_log_regex.regex_set.matches(write_qos_sample);

        let capture = dds_log_regex.regex[1].captures(write_qos_sample).unwrap();

        assert!(matches.matched(1));
        assert_eq!(&capture["year"], "2021");
        assert_eq!(&capture["month"], "12");
        assert_eq!(&capture["day"], "07");
        assert_eq!(&capture["hour"], "22");
        assert_eq!(&capture["min"], "19");
        assert_eq!(&capture["sec"], "48");
        assert_eq!(&capture["timezone"], "0000");
        assert_eq!(&capture["timestamp"], "1638915588.898675");
        assert_eq!(&capture["thread"], "main");
        assert_eq!(&capture["rw"], "WRITER");
        assert_eq!(&capture["system_id"], "428f812:7b:1");
        assert_eq!(&capture["rw_id"], "2302");
        assert_eq!(&capture["topic"], "d_sampleChain");
        assert_eq!(&capture["type"], "durabilityModule2::d_sampleChain_s");
        assert_eq!(&capture["presentation"], "1:0:0");
        assert_eq!(&capture["partition"], "durabilityPartition");
        assert_eq!(&capture["qos_durability"], "0");
        assert_eq!(
            &capture["durability_service"],
            "0.000000000:{0:1}:{-1:-1:-1}"
        );
        assert_eq!(&capture["deadline"], "2147483647.999999999");
        assert_eq!(&capture["latency_budget"], "0.000000000");
        assert_eq!(&capture["liveliness"], "0:0.000000000");
        assert_eq!(&capture["qos_reliability"], "1:1.000000000");
        assert_eq!(&capture["destination_order"], "0");
        assert_eq!(&capture["history"], "1:1");
        assert_eq!(&capture["resource_limits"], "1:-1:-1");
        assert_eq!(&capture["transport_priority"], "0");
        assert_eq!(&capture["lifespan"], "2147483647.999999999");
        assert_eq!(&capture["ownership"], "0");
        assert_eq!(&capture["ownership_strength"], "0");
        assert_eq!(
            &capture["writer_data_lifecycle"],
            "1,2147483647.999999999,2147483647.999999999"
        );
        assert_eq!(&capture["relaxed_qos_matching"], "0");
        assert_eq!(&capture["synchronous_endpoint"], "0");
    }

    #[test]
    fn dds_log_regex_reader_qos() {
        let dds_log_regex = DdsiLogRegex::new();
        let reader_qos_sample = "2022-01-23T14:11:29+0000 1642947089.987560/    (anon): READER 5bbed783:7b:1:3907 QOS={topic=Test_logevent_logLevel_418de7a5,type=Test::logevent_logLevel_418de7a5,presentation=0:0:0,partition={nile.Test.data},durability=2,durability_service=0.000000000:{0:100}:{-1:-1:-1},deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:2147483647.999999999,reliability=1:0.100000000,destination_order=0,history=0:100,resource_limits=-1:-1:-1,transport_priority=0,lifespan=2147483647.999999999,ownership=0,time_based_filter=0.000000000,reader_data_lifecycle=2147483647.999999999:2147483647.999999999:0:1:1,relaxed_qos_matching=0,reader_lifespan={0,2147483647.999999999},subscription_keys={0,{}},share={0,},synchronous_endpoint=0}";

        let matches = dds_log_regex.regex_set.matches(reader_qos_sample);

        let capture = dds_log_regex.regex[2].captures(reader_qos_sample).unwrap();

        assert!(matches.matched(2));
        assert_eq!(&capture["year"], "2022");
        assert_eq!(&capture["month"], "01");
        assert_eq!(&capture["day"], "23");
        assert_eq!(&capture["hour"], "14");
        assert_eq!(&capture["min"], "11");
        assert_eq!(&capture["sec"], "29");
        assert_eq!(&capture["timezone"], "0000");
        assert_eq!(&capture["timestamp"], "1642947089.987560");
        assert_eq!(&capture["thread"], "(anon)");
        assert_eq!(&capture["rw"], "READER");
        assert_eq!(&capture["system_id"], "5bbed783:7b:1");
        assert_eq!(&capture["rw_id"], "3907");
        assert_eq!(&capture["topic"], "Test_logevent_logLevel_418de7a5");
        assert_eq!(&capture["type"], "Test::logevent_logLevel_418de7a5");
        assert_eq!(&capture["partition"], "nile.Test.data");
        assert_eq!(&capture["synchronous_endpoint"], "0");
    }

    #[test]
    fn dds_log_regex_writer_sedp_st0() {
        let dds_log_regex = DdsiLogRegex::new();
        let sedp_st0_sample = "2021-12-07T22:22:48+0000 1638915768.903511/dq.builtin: SEDP ST0 7efc2093:7b:1:302 reliable transient writer: __BUILT-IN PARTITION__.DCPSParticipant/kernelModule::v_participantInfo p(open) NEW (as 239.255.0.1:7401 139.229.170.24:37673) QOS={topic=DCPSParticipant,type=kernelModule::v_participantInfo,presentation=1:0:0,partition={__BUILT-IN PARTITION__},durability=2,durability_service=0.000000000:{0:1}:{-1:-1:-1},deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:0.000000000,reliability=1:0.000000000,destination_order=0,history=1:-1,resource_limits=-1:-1:-1,transport_priority=0,lifespan=2147483647.999999999,ownership=0,ownership_strength=0,writer_data_lifecycle={1,2147483647.999999999,2147483647.999999999},relaxed_qos_matching=0,synchronous_endpoint=0}";

        let matches = dds_log_regex.regex_set.matches(sedp_st0_sample);

        assert!(matches.matched(3));

        let capture = dds_log_regex.regex[3].captures(sedp_st0_sample).unwrap();

        assert_eq!(&capture["year"], "2021");
        assert_eq!(&capture["month"], "12");
        assert_eq!(&capture["day"], "07");
        assert_eq!(&capture["hour"], "22");
        assert_eq!(&capture["min"], "22");
        assert_eq!(&capture["sec"], "48");
        assert_eq!(&capture["timezone"], "0000");
        assert_eq!(&capture["timestamp"], "1638915768.903511");
        assert_eq!(&capture["system_id"], "7efc2093:7b:1");
        assert_eq!(&capture["rw_id"], "302");
        assert_eq!(&capture["reliability"], "reliable");
        assert_eq!(&capture["durability"], "transient");
        assert_eq!(&capture["rw"], "writer");
        assert_eq!(
            &capture["discard"],
            "__BUILT-IN PARTITION__.DCPSParticipant/kernelModule::v_participantInfo"
        );
        assert_eq!(&capture["subnet"], "239.255.0.1");
        assert_eq!(&capture["subnet_port"], "7401");
        assert_eq!(&capture["hostname"], "139.229.170.24");
        assert_eq!(&capture["hostname_port"], "37673");
        assert_eq!(&capture["topic"], "DCPSParticipant");
        assert_eq!(&capture["type"], "kernelModule::v_participantInfo");
        assert_eq!(&capture["presentation"], "1:0:0");
        assert_eq!(&capture["partition"], "__BUILT-IN PARTITION__");
        assert_eq!(&capture["qos_durability"], "2");
        assert_eq!(
            &capture["durability_service"],
            "0.000000000:{0:1}:{-1:-1:-1}"
        );
        assert_eq!(&capture["deadline"], "2147483647.999999999");
        assert_eq!(&capture["latency_budget"], "0.000000000");
        assert_eq!(&capture["liveliness"], "0:0.000000000");
        assert_eq!(&capture["qos_reliability"], "1:0.000000000");
        assert_eq!(&capture["destination_order"], "0");
        assert_eq!(&capture["history"], "1:-1");
        assert_eq!(&capture["resource_limits"], "-1:-1:-1");
        assert_eq!(&capture["transport_priority"], "0");
        assert_eq!(&capture["lifespan"], "2147483647.999999999");
        assert_eq!(&capture["ownership"], "0");
        assert_eq!(&capture["ownership_strength"], "0");
        assert_eq!(
            &capture["writer_data_lifecycle"],
            "1,2147483647.999999999,2147483647.999999999"
        );
        assert_eq!(&capture["relaxed_qos_matching"], "0");
        assert_eq!(&capture["synchronous_endpoint"], "0");
    }

    #[test]
    fn dds_log_regex_reader_sedp_st0() {
        let dds_log_regex = DdsiLogRegex::new();
        let sedp_st0_sample = "2022-01-23T14:11:29+0000 1642947089.904222/dq.builtin: SEDP ST0 745ad3d:7b:1:5507 reliable transient reader: nile.Test.data.Test_logevent_summaryState_782ec3fd/Test::logevent_summaryState_782ec3fd p(open) NEW (as 239.255.0.1:7401 172.17.0.4:39948) QOS={topic=Test_logevent_summaryState_782ec3fd,type=Test::logevent_summaryState_782ec3fd,presentation=0:0:0,partition={nile.Test.data},durability=2,durability_service=0.000000000:{0:100}:{-1:-1:-1},deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:2147483647.999999999,reliability=1:0.100000000,destination_order=0,history=0:100,resource_limits=-1:-1:-1,transport_priority=0,lifespan=2147483647.999999999,ownership=0,time_based_filter=0.000000000,reader_data_lifecycle=2147483647.999999999:2147483647.999999999:0:1:1,relaxed_qos_matching=0,reader_lifespan={0,2147483647.999999999},subscription_keys={0,{}},share={0,},synchronous_endpoint=0}";

        let matches = dds_log_regex.regex_set.matches(sedp_st0_sample);

        assert!(matches.matched(4));

        let capture = dds_log_regex.regex[4].captures(sedp_st0_sample).unwrap();

        assert_eq!(&capture["year"], "2022");
        assert_eq!(&capture["month"], "01");
        assert_eq!(&capture["day"], "23");
        assert_eq!(&capture["hour"], "14");
        assert_eq!(&capture["min"], "11");
        assert_eq!(&capture["sec"], "29");
        assert_eq!(&capture["timezone"], "0000");
        assert_eq!(&capture["timestamp"], "1642947089.904222");
        assert_eq!(&capture["system_id"], "745ad3d:7b:1");
        assert_eq!(&capture["rw_id"], "5507");
        assert_eq!(&capture["reliability"], "reliable");
        assert_eq!(&capture["durability"], "transient");
        assert_eq!(&capture["rw"], "reader");
        assert_eq!(
            &capture["discard"],
            "nile.Test.data.Test_logevent_summaryState_782ec3fd/Test::logevent_summaryState_782ec3fd"
        );
        assert_eq!(&capture["subnet"], "239.255.0.1");
        assert_eq!(&capture["subnet_port"], "7401");
        assert_eq!(&capture["hostname"], "172.17.0.4");
        assert_eq!(&capture["hostname_port"], "39948");
        assert_eq!(&capture["topic"], "Test_logevent_summaryState_782ec3fd");
        assert_eq!(&capture["type"], "Test::logevent_summaryState_782ec3fd");
        assert_eq!(&capture["presentation"], "0:0:0");
        assert_eq!(&capture["partition"], "nile.Test.data");
        assert_eq!(&capture["qos_durability"], "2");
        assert_eq!(
            &capture["durability_service"],
            "0.000000000:{0:100}:{-1:-1:-1}"
        );
        assert_eq!(&capture["deadline"], "2147483647.999999999");
        assert_eq!(&capture["latency_budget"], "0.000000000");
        assert_eq!(&capture["liveliness"], "0:2147483647.999999999");
        assert_eq!(&capture["qos_reliability"], "1:0.100000000");
        assert_eq!(&capture["destination_order"], "0");
        assert_eq!(&capture["history"], "0:100");
        assert_eq!(&capture["resource_limits"], "-1:-1:-1");
        assert_eq!(&capture["transport_priority"], "0");
        assert_eq!(&capture["lifespan"], "2147483647.999999999");
        assert_eq!(&capture["ownership"], "0");
        assert_eq!(&capture["synchronous_endpoint"], "0");
    }

    #[test]
    fn dds_log_regex_reliable_volatile_reader_sedp_st0() {
        let dds_log_regex = DdsiLogRegex::new();
        let sedp_st0_sample = "2022-01-23T14:11:29+0000 1642947089.895283/dq.builtin: SEDP ST0 745ad3d:7b:1:3b07 reliable volatile reader: nile.Test.cmd.Test_command_start_cc827fa3/Test::command_start_cc827fa3 p(open) NEW (as 239.255.0.1:7401 172.17.0.4:39948) QOS={topic=Test_command_start_cc827fa3,type=Test::command_start_cc827fa3,presentation=0:0:0,partition={nile.Test.cmd},durability=0,deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:2147483647.999999999,reliability=1:0.100000000,destination_order=0,history=0:100,resource_limits=-1:-1:-1,transport_priority=0,ownership=0,time_based_filter=0.000000000,reader_data_lifecycle=2147483647.999999999:2147483647.999999999:0:1:1,relaxed_qos_matching=0,reader_lifespan={0,2147483647.999999999},subscription_keys={0,{}},share={0,},synchronous_endpoint=0}";

        let matches = dds_log_regex.regex_set.matches(sedp_st0_sample);

        assert!(matches.matched(4));

        let capture = dds_log_regex.regex[4].captures(sedp_st0_sample).unwrap();

        assert_eq!(&capture["year"], "2022");
        assert_eq!(&capture["month"], "01");
        assert_eq!(&capture["day"], "23");
        assert_eq!(&capture["hour"], "14");
        assert_eq!(&capture["min"], "11");
        assert_eq!(&capture["sec"], "29");
        assert_eq!(&capture["timezone"], "0000");
        assert_eq!(&capture["timestamp"], "1642947089.895283");
        assert_eq!(&capture["system_id"], "745ad3d:7b:1");
        assert_eq!(&capture["rw_id"], "3b07");
        assert_eq!(&capture["reliability"], "reliable");
        assert_eq!(&capture["durability"], "volatile");
        assert_eq!(&capture["rw"], "reader");
        assert_eq!(
            &capture["discard"],
            "nile.Test.cmd.Test_command_start_cc827fa3/Test::command_start_cc827fa3"
        );
        assert_eq!(&capture["subnet"], "239.255.0.1");
        assert_eq!(&capture["subnet_port"], "7401");
        assert_eq!(&capture["hostname"], "172.17.0.4");
        assert_eq!(&capture["hostname_port"], "39948");
        assert_eq!(&capture["topic"], "Test_command_start_cc827fa3");
        assert_eq!(&capture["type"], "Test::command_start_cc827fa3");
        assert_eq!(&capture["presentation"], "0:0:0");
        assert_eq!(&capture["partition"], "nile.Test.cmd");
        assert_eq!(&capture["qos_durability"], "0");
        assert_eq!(&capture["deadline"], "2147483647.999999999");
        assert_eq!(&capture["latency_budget"], "0.000000000");
        assert_eq!(&capture["liveliness"], "0:2147483647.999999999");
        assert_eq!(&capture["qos_reliability"], "1:0.100000000");
        assert_eq!(&capture["destination_order"], "0");
        assert_eq!(&capture["history"], "0:100");
        assert_eq!(&capture["resource_limits"], "-1:-1:-1");
        assert_eq!(&capture["transport_priority"], "0");
        assert_eq!(&capture["ownership"], "0");
        assert_eq!(&capture["synchronous_endpoint"], "0");
    }

    #[test]
    fn own_ip() {
        let dds_log_regex = DdsiLogRegex::new();
        let own_ip_sample =
            "2022-01-23T14:08:13+0000 1642946893.209853/      main: ownip: 172.17.0.3";
        let matches = dds_log_regex.regex_set.matches(own_ip_sample);

        assert!(matches.matched(5));

        let capture = dds_log_regex.regex[5].captures(own_ip_sample).unwrap();

        assert_eq!(&capture["hostname"], "172.17.0.3");
    }

    #[test]
    fn writer_sedp_st3() {
        let dds_log_regex = DdsiLogRegex::new();
        let writer_sedp_st3 =
        "2022-01-23T14:11:51+0000 1642947111.749832/dq.builtin: SEDP ST3 745ad3d:7b:1:4802delete_proxy_writer (745ad3d:7b:1:4802) - deleting";

        let matches = dds_log_regex.regex_set.matches(writer_sedp_st3);

        assert!(matches.matched(6));

        let capture = dds_log_regex.regex[6].captures(writer_sedp_st3).unwrap();

        assert_eq!(&capture["system_id"], "745ad3d:7b:1");
        assert_eq!(&capture["rw_id"], "4802");
    }

    #[test]
    fn reader_sedp_st3() {
        let dds_log_regex = DdsiLogRegex::new();
        let reader_sedp_st3 =
        "2022-01-23T14:11:51+0000 1642947111.745674/dq.builtin: SEDP ST3 745ad3d:7b:1:3007delete_proxy_reader (745ad3d:7b:1:3007) - deleting";

        let matches = dds_log_regex.regex_set.matches(reader_sedp_st3);

        assert!(matches.matched(7));

        let capture = dds_log_regex.regex[7].captures(reader_sedp_st3).unwrap();

        assert_eq!(&capture["system_id"], "745ad3d:7b:1");
        assert_eq!(&capture["rw_id"], "3007");
    }

    #[test]
    fn parse_match() {
        let dds_log_regex = DdsiLogRegex::new();
        let text_samples_match = [
            "2022-01-23T14:08:13+0000 1642946893.209853/      main: ownip: 172.17.0.3",
            "2021-12-07T22:19:48+0000 1638915588.796443/      main: handleParticipantsSelf: found 428f812:7b:1 (self)",
            "2021-12-07T22:19:48+0000 1638915588.898675/      main: WRITER 428f812:7b:1:2302 QOS={topic=d_sampleChain,type=durabilityModule2::d_sampleChain_s,presentation=1:0:0,partition={durabilityPartition},durability=0,durability_service=0.000000000:{0:1}:{-1:-1:-1},deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:0.000000000,reliability=1:1.000000000,destination_order=0,history=1:1,resource_limits=1:-1:-1,transport_priority=0,lifespan=2147483647.999999999,ownership=0,ownership_strength=0,writer_data_lifecycle={1,2147483647.999999999,2147483647.999999999},relaxed_qos_matching=0,synchronous_endpoint=0}",
            "2021-12-07T22:22:48+0000 1638915768.903511/dq.builtin: SEDP ST0 7efc2093:7b:1:302 reliable transient writer: __BUILT-IN PARTITION__.DCPSParticipant/kernelModule::v_participantInfo p(open) NEW (as 239.255.0.1:7401 139.229.170.24:37673) QOS={topic=DCPSParticipant,type=kernelModule::v_participantInfo,presentation=1:0:0,partition={__BUILT-IN PARTITION__},durability=2,durability_service=0.000000000:{0:1}:{-1:-1:-1},deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:0.000000000,reliability=1:0.000000000,destination_order=0,history=1:-1,resource_limits=-1:-1:-1,transport_priority=0,lifespan=2147483647.999999999,ownership=0,ownership_strength=0,writer_data_lifecycle={1,2147483647.999999999,2147483647.999999999},relaxed_qos_matching=0,synchronous_endpoint=0}",
            "2022-01-23T14:11:29+0000 1642947089.895283/dq.builtin: SEDP ST0 745ad3d:7b:1:3b07 reliable volatile reader: nile.Test.cmd.Test_command_start_cc827fa3/Test::command_start_cc827fa3 p(open) NEW (as 239.255.0.1:7401 172.17.0.4:39948) QOS={topic=Test_command_start_cc827fa3,type=Test::command_start_cc827fa3,presentation=0:0:0,partition={nile.Test.cmd},durability=0,deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:2147483647.999999999,reliability=1:0.100000000,destination_order=0,history=0:100,resource_limits=-1:-1:-1,transport_priority=0,ownership=0,time_based_filter=0.000000000,reader_data_lifecycle=2147483647.999999999:2147483647.999999999:0:1:1,relaxed_qos_matching=0,reader_lifespan={0,2147483647.999999999},subscription_keys={0,{}},share={0,},synchronous_endpoint=0}",
            "2022-01-23T14:11:29+0000 1642947089.987961/    (anon): READER 5bbed783:7b:1:3b07 QOS={topic=Test_logevent_summaryState_782ec3fd,type=Test::logevent_summaryState_782ec3fd,presentation=0:0:0,partition={nile.Test.data},durability=2,durability_service=0.000000000:{0:100}:{-1:-1:-1},deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:2147483647.999999999,reliability=1:0.100000000,destination_order=0,history=0:100,resource_limits=-1:-1:-1,transport_priority=0,lifespan=2147483647.999999999,ownership=0,time_based_filter=0.000000000,reader_data_lifecycle=2147483647.999999999:2147483647.999999999:0:1:1,relaxed_qos_matching=0,reader_lifespan={0,2147483647.999999999},subscription_keys={0,{}},share={0,},synchronous_endpoint=0}",
            "2022-01-23T14:11:51+0000 1642947111.749832/dq.builtin: SEDP ST3 745ad3d:7b:1:4802delete_proxy_writer (745ad3d:7b:1:4802) - deleting",
            "2022-01-23T14:11:51+0000 1642947111.745674/dq.builtin: SEDP ST3 745ad3d:7b:1:3007delete_proxy_reader (745ad3d:7b:1:3007) - deleting",
            ];
        let timestamps = [
            "1642946893.209853",
            "1638915588.796443",
            "1638915588.898675",
            "1638915768.903511",
            "1642947089.895283",
            "1642947089.987961",
            "1642947111.749832",
            "1642947111.745674",
        ];

        for (text, timestamp) in text_samples_match.iter().zip(timestamps.iter()) {
            let capture = dds_log_regex.parse(text).unwrap();
            assert_eq!(&capture.get_capture()["timestamp"], *timestamp);
        }
    }
    #[test]
    #[should_panic]
    fn parse_no_match() {
        let dds_log_regex = DdsiLogRegex::new();
        let text_sample_no_match =
            "2022-01-20T13:24:36+0000 1642685076.168332/dq.builtin: thread_cputime 1260.618874505";

        dds_log_regex.parse(text_sample_no_match).unwrap();
    }
}
