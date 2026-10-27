//! `decoder-dump` (S-407, test-strategy §4.2) — the Rust side of `difftest fuzzdiff`.
//!
//! stdin: JSON lines `{"id": …, "chunks_b64": ["…", …]}`; stdout: one JSON line per input
//! `{"id": …, "events": [{"elm_b64": …, "evt": {"frame_b64": …} | {"unmarshal": msg} |
//! {"serialize": msg}}], "error": bool, "error_chunk": n|null, "error_text": s|null}`.
//! The chunks are fed exactly like `taky-server` `conn::read_half` (see `taky_fuzz_common::run_stream`).
use std::io::{BufRead, Write};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use taky_fuzz_common::{EventOutcome, run_stream};

fn one(line: &str) -> Result<Value, String> {
    let v: Value = serde_json::from_str(line).map_err(|e| format!("bad input line: {e}"))?;
    let chunks: Vec<Vec<u8>> = v
        .get("chunks_b64")
        .and_then(Value::as_array)
        .ok_or("missing chunks_b64")?
        .iter()
        .map(|c| {
            B64.decode(c.as_str().unwrap_or(""))
                .map_err(|e| e.to_string())
        })
        .collect::<Result<_, _>>()?;
    let refs: Vec<&[u8]> = chunks.iter().map(Vec::as_slice).collect();
    let d = run_stream(&refs);
    let events: Vec<Value> = d
        .events
        .iter()
        .map(|e| {
            let evt = match &e.evt {
                EventOutcome::Frame(f) => json!({ "frame_b64": B64.encode(f) }),
                EventOutcome::Unmarshal(m) => json!({ "unmarshal": m }),
                EventOutcome::Serialize(m) => json!({ "serialize": m }),
            };
            json!({ "elm_b64": B64.encode(&e.elm), "evt": evt })
        })
        .collect();
    Ok(json!({
        "id": v.get("id").cloned().unwrap_or(Value::Null),
        "events": events,
        "error": d.error,
        "error_chunk": d.error_chunk,
        "error_text": d.error_text,
    }))
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout().lock());
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
        if line.trim().is_empty() {
            continue;
        }
        let v = one(&line).unwrap_or_else(|e| json!({ "harness_error": e }));
        let _ = writeln!(out, "{v}");
        let _ = out.flush();
    }
}
