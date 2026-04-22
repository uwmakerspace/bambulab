use crate::message::Print;
use crate::print_data_parse::parse_print_data_from_value;
use crate::Message;

pub(crate) fn parse_message(payload: &[u8]) -> Message {
    if let Ok(parsed_message) = serde_json::from_slice::<Message>(payload) {
        return parsed_message;
    }

    let Ok(message_str) = String::from_utf8(payload.to_vec()) else {
        return Message::Unknown(None);
    };

    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&message_str) {
        if let Some(p) = val.get("print") {
            if let Some(data) = parse_print_data_from_value(p) {
                return Message::Print(Box::new(Print { print: data }));
            }
        }
    }

    Message::Unknown(Some(message_str))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_message_unknown_string() {
        let payload = br#"{ "hello": "world" }"#;
        let result = parse_message(payload);
        assert_eq!(
            result,
            Message::Unknown(Some(r#"{ "hello": "world" }"#.to_string()))
        );
    }

    #[test]
    fn test_parse_message_unknown_unparsable() {
        let result = parse_message(&[255, 255]);
        assert_eq!(result, Message::Unknown(None));
    }

    #[test]
    fn test_parse_message_print() {
        let payload = br#"{ "print": { "bed_temper": 17.40625, "wifi_signal": "-59dBm", "command": "push_status", "msg": 1, "sequence_id": "694" } }"#;
        let result = parse_message(payload);
        assert!(matches!(result, Message::Print(_)));
    }

    #[test]
    fn test_parse_message_info() {
        let payload = br#"{
                "info":{
                    "command":"get_version",
                    "sequence_id":"0",
                    "module":[
                        {
                            "name":"ota",
                            "project_name":"C11",
                            "sw_ver":"01.04.02.00",
                            "hw_ver":"OTA",
                            "sn":"01S00C123400001"
                        }
                    ],
                    "result":"success",
                    "reason":""
                }
            }"#;
        let result = parse_message(payload);
        assert!(matches!(result, Message::Info(_)));
    }

    #[test]
    fn test_parse_message_system() {
        let payload = br#"{
                "system": {
                  "command": "get_access_code",
                  "sequence_id": "0",
                  "access_code": "12312312",
                  "result": "success"
                }
              }"#;
        let result = parse_message(payload);
        assert!(matches!(result, Message::System(_)));
    }

    #[test]
    fn test_parse_message_info_with_product_name_and_missing_result_reason() {
        let payload = br#"{
                                "info": {
                                    "command": "get_version",
                                    "sequence_id": "0",
                                    "module": [
                                        {
                                            "name": "ota",
                                            "product_name": "X1C",
                                            "sw_ver": "01.09.01.00",
                                            "hw_ver": "OTA",
                                            "sn": "01S00C123400001",
                                            "new_ver": "01.09.02.00",
                                            "flag": 1,
                                            "visible": true
                                        }
                                    ]
                                }
                            }"#;
        let result = parse_message(payload);
        assert!(matches!(result, Message::Info(_)));
    }

    #[test]
    fn test_parse_message_print_lenient_when_strict_nested_types_fail() {
        let payload =
            br#"{"print":{"gcode_state":"RUNNING","mc_percent":42,"online":"not-an-object"}}"#;
        let result = parse_message(payload);
        match result {
            Message::Print(p) => {
                assert_eq!(p.print.gcode_state.as_deref(), Some("RUNNING"));
                assert_eq!(p.print.mc_percent, Some(42));
            }
            other => panic!("expected Print, got {other:?}"),
        }
    }

    #[test]
    fn test_parse_message_print_with_h2d_shape() {
        let payload = br#"{
                                "print": {
                                    "command": "push_status",
                                    "online": {
                                        "ahb": true,
                                        "ext": false,
                                        "ctc": true,
                                        "version": 124
                                    },
                                    "upload": {
                                        "status": "idle",
                                        "progress": 0,
                                        "message": "",
                                        "file_size": 123456,
                                        "finish_size": 0,
                                        "speed": 0,
                                        "task_id": "abc123"
                                    },
                                    "vt_tray": {
                                        "id": "254",
                                        "tag_uid": "",
                                        "tray_id_name": "PLA Basic",
                                        "tray_info_idx": "GFA00",
                                        "tray_type": "PLA",
                                        "tray_sub_brands": "Bambu",
                                        "tray_color": "FFFFFFFF",
                                        "tray_weight": "1000",
                                        "tray_diameter": "1.75",
                                        "bed_temp_type": "0",
                                        "bed_temp": "35",
                                        "nozzle_temp_max": "240",
                                        "nozzle_temp_min": "200",
                                        "xcam_info": "",
                                        "tray_uuid": "",
                                        "remain": 100,
                                        "cali_idx": 0,
                                        "cols": ["FFFFFFFF"],
                                        "ctype": 0,
                                        "drying_temp": "0",
                                        "drying_time": "0",
                                        "total_len": 330000
                                    }
                                }
                            }"#;
        let result = parse_message(payload);
        assert!(matches!(result, Message::Print(_)));
    }
}
