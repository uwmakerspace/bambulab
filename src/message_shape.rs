//! Aggregates observed JSON path → value-type shapes per machine type (for validating serde optionality).

use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io;
use std::path::Path;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::Message;

const MESSAGE_SCHEMA_SUMMARY_PATH: &str = "logs/bambu_message_schema_summary.json";

#[derive(Debug, Default, Serialize, Deserialize)]
struct MessageSchemaSummary {
    machine_types: BTreeMap<String, BTreeMap<String, SchemaBucket>>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SchemaBucket {
    messages_seen: u64,
    paths: BTreeMap<String, SchemaPathStat>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct SchemaPathStat {
    seen: u64,
    value_types: BTreeMap<String, u64>,
}

fn schema_log_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Append observed JSON shapes for `message` under `machine_type` to `logs/bambu_message_schema_summary.json`.
pub fn log_message_shape(machine_type: &str, message: &Message) -> io::Result<()> {
    let (message_kind, payload) = message_shape_payload(message);
    let mut path_types = HashMap::new();

    if let Some(value) = payload {
        collect_value_paths(&value, "", &mut path_types);
    }

    let _guard = match schema_log_lock().lock() {
        Ok(g) => g,
        Err(e) => e.into_inner(),
    };

    update_schema_summary(machine_type, &message_kind, &path_types)
}

fn update_schema_summary(
    machine_type: &str,
    message_kind: &str,
    path_types: &HashMap<String, String>,
) -> io::Result<()> {
    let path = Path::new(MESSAGE_SCHEMA_SUMMARY_PATH);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut summary = read_schema_summary(path).unwrap_or_default();
    let mut changed = false;

    let machine_entry = summary
        .machine_types
        .entry(machine_type.to_string())
        .or_default();
    let bucket = machine_entry.entry(message_kind.to_string()).or_default();

    if bucket.messages_seen == 0 {
        bucket.messages_seen = 1;
        changed = true;
    }

    for (path_key, value_type) in path_types {
        let stat = bucket.paths.entry(path_key.clone()).or_default();

        if stat.seen == 0 {
            stat.seen = 1;
            changed = true;
        }

        if value_type == "mixed" {
            if stat.value_types.len() != 1 || !stat.value_types.contains_key("mixed") {
                stat.value_types.clear();
                stat.value_types.insert("mixed".to_string(), 1);
                changed = true;
            }
            continue;
        }

        if stat.value_types.contains_key("mixed") {
            continue;
        }

        if !stat.value_types.contains_key(value_type) {
            stat.value_types.insert(value_type.clone(), 1);
            changed = true;
        }
    }

    if !changed {
        return Ok(());
    }

    let serialized = serde_json::to_string_pretty(&summary).map_err(io::Error::other)?;
    fs::write(path, serialized)
}

fn read_schema_summary(path: &Path) -> Option<MessageSchemaSummary> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn message_shape_payload(message: &Message) -> (String, Option<serde_json::Value>) {
    match message {
        Message::Connected => ("connected".to_string(), None),
        Message::Disconnected => ("disconnected".to_string(), None),
        Message::Connecting => ("connecting".to_string(), None),
        Message::Reconnecting => ("reconnecting".to_string(), None),
        Message::Print(print) => ("print".to_string(), serde_json::to_value(&print.print).ok()),
        Message::Info(info) => ("info".to_string(), serde_json::to_value(info).ok()),
        Message::System(system) => ("system".to_string(), serde_json::to_value(system).ok()),
        Message::Unknown(Some(raw)) => {
            let parsed = serde_json::from_str::<serde_json::Value>(raw);
            match parsed {
                Ok(val) => {
                    if let Some(print) = val.get("print") {
                        ("unknown.print".to_string(), Some(print.clone()))
                    } else if let Some(info) = val.get("info") {
                        ("unknown.info".to_string(), Some(info.clone()))
                    } else if let Some(system) = val.get("system") {
                        ("unknown.system".to_string(), Some(system.clone()))
                    } else {
                        ("unknown.other".to_string(), Some(val))
                    }
                }
                Err(_) => ("unknown.unparsed".to_string(), None),
            }
        }
        Message::Unknown(None) => ("unknown.none".to_string(), None),
    }
}

fn collect_value_paths(
    value: &serde_json::Value,
    path: &str,
    path_types: &mut HashMap<String, String>,
) {
    let ty = json_type(value);

    if !path.is_empty() {
        merge_path_type(path_types, path.to_string(), ty.to_string());
    }

    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let next = if path.is_empty() {
                    key.to_string()
                } else {
                    format!("{path}.{key}")
                };
                collect_value_paths(child, &next, path_types);
            }
        }
        serde_json::Value::Array(items) => {
            let next = if path.is_empty() {
                "[]".to_string()
            } else {
                format!("{path}[]")
            };

            merge_path_type(path_types, next.clone(), "array".to_string());

            for item in items {
                collect_value_paths(item, &next, path_types);
            }
        }
        _ => {
            if path.is_empty() {
                merge_path_type(path_types, "$".to_string(), ty.to_string());
            }
        }
    }
}

fn merge_path_type(path_types: &mut HashMap<String, String>, path: String, ty: String) {
    if let Some(existing) = path_types.get_mut(&path) {
        if *existing != ty {
            *existing = "mixed".to_string();
        }
        return;
    }

    path_types.insert(path, ty);
}

fn json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "bool",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}
