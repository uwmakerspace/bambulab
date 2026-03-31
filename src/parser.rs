use crate::Message;

pub(crate) fn parse_message(message: &paho_mqtt::Message) -> Message {
    let payload = message.payload();

    if let Ok(parsed_message) = serde_json::from_slice::<Message>(payload) {
        parsed_message
    } else {
        if let Ok(message_str) = String::from_utf8(payload.to_vec()) {
            return Message::Unknown(Some(message_str));
        }
        Message::Unknown(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_message_unknown_string() {
        let message = paho_mqtt::Message::new(
            "device/123456789/report",
            r#"{ "hello": "world" }"#,
            paho_mqtt::QOS_2,
        );

        let result = parse_message(&message);

        assert_eq!(
            result,
            Message::Unknown(Some(r#"{ "hello": "world" }"#.to_string()))
        );
    }

    #[test]
    fn test_parse_message_unknown_unparsable() {
        let message =
            paho_mqtt::Message::new("device/123456789/report", vec![255, 255], paho_mqtt::QOS_2);

        let result = parse_message(&message);

        assert_eq!(result, Message::Unknown(None));
    }

    #[test]
    fn test_parse_message_print() {
        let message = paho_mqtt::Message::new(
            "device/123456789/report",
            r#"{ "print": { "bed_temper": 17.40625, "wifi_signal": "-59dBm", "command": "push_status", "msg": 1, "sequence_id": "694" } }"#,
            paho_mqtt::QOS_2,
        );

        let result = parse_message(&message);

        assert!(matches!(result, Message::Print(_)));
    }

    #[test]
    fn test_parse_message_info() {
        let message = paho_mqtt::Message::new(
            "device/123456789/report",
            r#"{
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
            }"#,
            paho_mqtt::QOS_2,
        );

        let result = parse_message(&message);

        assert!(matches!(result, Message::Info(_)));
    }

    #[test]
    fn test_parse_message_system() {
        let message = paho_mqtt::Message::new(
            "device/123456789/report",
            r#"{
                "system": {
                  "command": "get_access_code",
                  "sequence_id": "0",
                  "access_code": "12312312",
                  "result": "success"
                }
              }"#,
            paho_mqtt::QOS_2,
        );

        let result = parse_message(&message);

        assert!(matches!(result, Message::System(_)));
    }

    #[test]
    fn test_parse_message_info_with_product_name_and_missing_result_reason() {
        let message = paho_mqtt::Message::new(
            "device/123456789/report",
            r#"{
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
                            }"#,
            paho_mqtt::QOS_2,
        );

        let result = parse_message(&message);

        assert!(matches!(result, Message::Info(_)));
    }

    #[test]
    fn test_parse_message_print_with_h2d_shape() {
        let message = paho_mqtt::Message::new(
            "device/123456789/report",
            r#"{
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
                            }"#,
            paho_mqtt::QOS_2,
        );

        let result = parse_message(&message);

        assert!(matches!(result, Message::Print(_)));
    }
}
