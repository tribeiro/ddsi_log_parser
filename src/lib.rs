use regex::{Regex, RegexSet};

/// Provide a set of regular expressions for parsing ddsi log entries.
struct DdsiLogRegex {
    regex_set: RegexSet,
    regex: Vec<Regex>,
}

const HEADER_REGEX: &str = r"(?P<year>\d{4})-(?P<month>\d{2})-(?P<day>\d{2})T(?P<hour>\d{2}):(?P<min>\d{2}):(?P<sec>\d{2})\+(?P<timezone>\d{4}) (?P<timestamp>[0-9]*\.[0-9]*)/";

const QOS_REGEX: &str = r"QOS=\{topic=(?P<topic>[a-zA-Z0-9_]*),type=(?P<type>[a-zA-Z0-9_:]*),presentation=(?P<presentation>[a-zA-Z0-9_:]*),partition=\{(?P<partition>[a-zA-Z0-9_:]*)\},durability=(?P<durability>[a-zA-Z0-9_:]*),durability_service=(?P<durability_service>[a-zA-Z0-9_:\{\}\.\-]*),deadline=(?P<deadline>[a-zA-Z0-9\.]*),latency_budget=(?P<latency_budget>[a-zA-Z0-9\.]*),liveliness=(?P<liveliness>[a-zA-Z0-9_:\.]*),reliability=(?P<reliability>[a-zA-Z0-9_:\.]*),destination_order=(?P<destination_order>[a-zA-Z0-9_:]*),history=(?P<history>[a-zA-Z0-9_:]*),resource_limits=(?P<resource_limits>[a-zA-Z0-9_:\-]*),transport_priority=(?P<transport_priority>[a-zA-Z0-9_:]*),lifespan=(?P<lifespan>[a-zA-Z0-9_:\.]*),ownership=(?P<ownership>[a-zA-Z0-9_:]*),ownership_strength=(?P<ownership_strength>[a-zA-Z0-9_:]*),writer_data_lifecycle=\{(?P<writer_data_lifecycle>[a-zA-Z0-9_:\.,]*)\},relaxed_qos_matching=(?P<relaxed_qos_matching>[a-zA-Z0-9_:]*),synchronous_endpoint=(?P<synchronous_endpoint>[a-zA-Z0-9_:]*)\}";

const SYSTEM_ID_REGEX: &str = r"(?P<system_id>[a-zA-Z0-9]{7}:[a-zA-Z0-9]{2}:[a-zA-Z0-9]{1})";
const RW_ID_REGEX: &str = r"(?P<rw_id>[a-zA-Z0-9]*)";

impl DdsiLogRegex {
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
        ])
        .unwrap();
        let regex = regex_set
            .patterns()
            .into_iter()
            .map(|pattern| Regex::new(pattern).unwrap())
            .collect();
        DdsiLogRegex { regex_set, regex }
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
        assert_eq!(&capture["durability"], "0");
        assert_eq!(
            &capture["durability_service"],
            "0.000000000:{0:1}:{-1:-1:-1}"
        );
        assert_eq!(&capture["deadline"], "2147483647.999999999");
        assert_eq!(&capture["latency_budget"], "0.000000000");
        assert_eq!(&capture["liveliness"], "0:0.000000000");
        assert_eq!(&capture["reliability"], "1:1.000000000");
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
}
