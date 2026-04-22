//! Lenient [`PrintData`](crate::message::PrintData) parsing when strict nested types fail.

use serde_json::Value;

use crate::message::PrintData;

/// Parse a `print` object from device report JSON.
///
/// Returns [`None`] if `p` is not a JSON object. Otherwise tries strict deserialization first,
/// then falls back to scalar field extraction (firmware often sends shapes that break nested types).
#[must_use]
pub fn parse_print_data_from_value(p: &Value) -> Option<PrintData> {
    if !p.is_object() {
        return None;
    }

    if let Ok(data) = serde_json::from_value::<PrintData>(p.clone()) {
        return Some(data);
    }

    Some(PrintData {
        gcode_state: json_str(p, "gcode_state"),
        gcode_file: json_str(p, "gcode_file"),
        subtask_name: json_str(p, "subtask_name"),
        mc_percent: json_i64(p, "mc_percent"),
        mc_remaining_time: json_i64(p, "mc_remaining_time"),
        layer_num: json_i64(p, "layer_num"),
        total_layer_num: json_i64(p, "total_layer_num"),
        print_error: json_i64(p, "print_error"),
        nozzle_temper: json_f64(p, "nozzle_temper"),
        nozzle_target_temper: json_i64(p, "nozzle_target_temper"),
        bed_temper: json_f64(p, "bed_temper"),
        bed_target_temper: json_i64(p, "bed_target_temper"),
        chamber_temper: json_i64(p, "chamber_temper"),
        hms: p
            .get("hms")
            .and_then(|v| serde_json::from_value(v.clone()).ok()),
        ams: p
            .get("ams")
            .and_then(|v| serde_json::from_value(v.clone()).ok()),
        ipcam: p
            .get("ipcam")
            .and_then(|v| serde_json::from_value(v.clone()).ok()),
        ..Default::default()
    })
}

fn json_str(obj: &Value, key: &str) -> Option<String> {
    obj.get(key)?.as_str().map(String::from)
}

fn json_f64(obj: &Value, key: &str) -> Option<f64> {
    obj.get(key)?.as_f64()
}

// Float fallbacks are firmware JSON values (temps, counters); truncation matches prior behavior.
#[allow(clippy::cast_possible_truncation)]
fn json_i64(obj: &Value, key: &str) -> Option<i64> {
    let v = obj.get(key)?;
    v.as_i64().or_else(|| v.as_f64().map(|f| f as i64))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn lenient_parses_when_online_has_wrong_shape() {
        let p = json!({
            "gcode_state": "RUNNING",
            "mc_percent": 42,
            "online": "not-an-object"
        });
        let strict = serde_json::from_value::<PrintData>(p.clone());
        assert!(strict.is_err(), "strict parse should fail");

        let data = parse_print_data_from_value(&p).expect("lenient parse");
        assert_eq!(data.gcode_state.as_deref(), Some("RUNNING"));
        assert_eq!(data.mc_percent, Some(42));
    }

    #[test]
    fn lenient_parses_ipcam_when_strict_fails() {
        let p = json!({
            "gcode_state": "IDLE",
            "online": "broken",
            "ipcam": {
                "rtsp_url": "disable",
                "mode_bits": 2
            }
        });
        assert!(serde_json::from_value::<PrintData>(p.clone()).is_err());
        let data = parse_print_data_from_value(&p).expect("lenient parse");
        let cam = data.ipcam.expect("ipcam");
        assert_eq!(cam.rtsp_url.as_deref(), Some("disable"));
        assert_eq!(cam.mode_bits, Some(2));
    }
}
