use regex::{Captures, Regex, RegexSet};

/// Provide a set of regular expressions and methods for parsing ddsi log
/// entries.
struct DdsiLogRegex {
    regex_set: RegexSet,
    regex: Vec<Regex>,
}

const HEADER_REGEX: &str = r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})\+(?P<timezone>\d{4}) (?P<timestamp>[0-9]*\.[0-9]*)/";
const QOS_REGEX: &str = r"QOS=\{topic=(?P<topic>[a-zA-Z0-9_]*),type=(?P<type>[a-zA-Z0-9_:]*),presentation=(?P<presentation>[a-zA-Z0-9_:]*),partition=\{(?P<partition>.*)\},durability=(?P<qos_durability>[a-zA-Z0-9_:]*),durability_service=(?P<durability_service>[a-zA-Z0-9_:\{\}\.\-]*),deadline=(?P<deadline>[a-zA-Z0-9\.]*),latency_budget=(?P<latency_budget>[a-zA-Z0-9\.]*),liveliness=(?P<liveliness>[a-zA-Z0-9_:\.]*),reliability=(?P<qos_reliability>[a-zA-Z0-9_:\.]*),destination_order=(?P<destination_order>[a-zA-Z0-9_:]*),history=(?P<history>[a-zA-Z0-9_:\-]*),resource_limits=(?P<resource_limits>[a-zA-Z0-9_:\-]*),transport_priority=(?P<transport_priority>[a-zA-Z0-9_:]*),lifespan=(?P<lifespan>[a-zA-Z0-9_:\.]*),ownership=(?P<ownership>[a-zA-Z0-9_:]*),ownership_strength=(?P<ownership_strength>[a-zA-Z0-9_:]*),writer_data_lifecycle=\{(?P<writer_data_lifecycle>[a-zA-Z0-9_:\.,]*)\},relaxed_qos_matching=(?P<relaxed_qos_matching>[a-zA-Z0-9_:]*),synchronous_endpoint=(?P<synchronous_endpoint>[a-zA-Z0-9_:]*)\}";
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
    fn new() -> DdsiLogRegex {
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
                r"      (?P<thread>[a-zA-Z0-9_\(\)]*): (?P<rw>[a-zA-Z0-9_]*) ",
                SYSTEM_ID_REGEX,
                r":",
                RW_ID_REGEX,
                r" ",
                QOS_REGEX,
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
                QOS_REGEX,
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
    fn parse<'a>(&self, text: &'a str) -> Option<Captures<'a>> {
        if self.regex_set.is_match(text) {
            let matches: Vec<_> = self.regex_set.matches(text).into_iter().collect();

            self.regex[matches[0]].captures(text)
        } else {
            None
        }
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
    fn dds_log_regex_sedp_st0() {
        let dds_log_regex = DdsiLogRegex::new();
        let sedp_st0_sample = "2021-12-07T22:22:48+0000 1638915768.903511/dq.builtin: SEDP ST0 7efc2093:7b:1:302 reliable transient writer: __BUILT-IN PARTITION__.DCPSParticipant/kernelModule::v_participantInfo p(open) NEW (as 239.255.0.1:7401 139.229.170.24:37673) QOS={topic=DCPSParticipant,type=kernelModule::v_participantInfo,presentation=1:0:0,partition={__BUILT-IN PARTITION__},durability=2,durability_service=0.000000000:{0:1}:{-1:-1:-1},deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:0.000000000,reliability=1:0.000000000,destination_order=0,history=1:-1,resource_limits=-1:-1:-1,transport_priority=0,lifespan=2147483647.999999999,ownership=0,ownership_strength=0,writer_data_lifecycle={1,2147483647.999999999,2147483647.999999999},relaxed_qos_matching=0,synchronous_endpoint=0}";

        let matches = dds_log_regex.regex_set.matches(sedp_st0_sample);
        let capture = dds_log_regex.regex[2].captures(sedp_st0_sample).unwrap();

        assert!(matches.matched(2));
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
    fn parse_match() {
        let dds_log_regex = DdsiLogRegex::new();
        let text_samples_match = [
            "2021-12-07T22:19:48+0000 1638915588.796443/      main: handleParticipantsSelf: found 428f812:7b:1 (self)",
            "2021-12-07T22:19:48+0000 1638915588.898675/      main: WRITER 428f812:7b:1:2302 QOS={topic=d_sampleChain,type=durabilityModule2::d_sampleChain_s,presentation=1:0:0,partition={durabilityPartition},durability=0,durability_service=0.000000000:{0:1}:{-1:-1:-1},deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:0.000000000,reliability=1:1.000000000,destination_order=0,history=1:1,resource_limits=1:-1:-1,transport_priority=0,lifespan=2147483647.999999999,ownership=0,ownership_strength=0,writer_data_lifecycle={1,2147483647.999999999,2147483647.999999999},relaxed_qos_matching=0,synchronous_endpoint=0}",
            "2021-12-07T22:22:48+0000 1638915768.903511/dq.builtin: SEDP ST0 7efc2093:7b:1:302 reliable transient writer: __BUILT-IN PARTITION__.DCPSParticipant/kernelModule::v_participantInfo p(open) NEW (as 239.255.0.1:7401 139.229.170.24:37673) QOS={topic=DCPSParticipant,type=kernelModule::v_participantInfo,presentation=1:0:0,partition={__BUILT-IN PARTITION__},durability=2,durability_service=0.000000000:{0:1}:{-1:-1:-1},deadline=2147483647.999999999,latency_budget=0.000000000,liveliness=0:0.000000000,reliability=1:0.000000000,destination_order=0,history=1:-1,resource_limits=-1:-1:-1,transport_priority=0,lifespan=2147483647.999999999,ownership=0,ownership_strength=0,writer_data_lifecycle={1,2147483647.999999999,2147483647.999999999},relaxed_qos_matching=0,synchronous_endpoint=0}",
            ];
        let timestamps = [
            "1638915588.796443",
            "1638915588.898675",
            "1638915768.903511",
        ];

        for (text, timestamp) in text_samples_match.iter().zip(timestamps.iter()) {
            let capture = dds_log_regex.parse(text).unwrap();
            assert_eq!(&capture["timestamp"], *timestamp);
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
