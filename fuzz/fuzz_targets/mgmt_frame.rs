//! `mgmt_frame` (S-407): the mgmt socket protocol (`taky-server::mgmt`, spec §13): the input is a
//! byte stream split at `\0` like the server does (the unterminated tail stays buffered), each frame
//! goes through `MgmtRequest::parse` and the reply is built as the server builds it
//! (`invalid_reply` / `{"error": …}` / `reply_frame`); any JSON value is also dumped with
//! `pyjson::dumps` (big numbers, `ensure_ascii`). The frame splitter itself is private to the
//! connection task, so it is re-implemented here (spec: split at `\0`).
//! Invariants: no panic; a reply is ASCII and has exactly one `\0`, at the end.
#![no_main]
use libfuzzer_sys::fuzz_target;
use serde_json::{Value, json};
use taky_server::MgmtRequest;
use taky_server::mgmt::reply_frame;

fn check(frame: &[u8]) {
    let n = frame.len();
    assert!(n > 0 && frame[n - 1] == 0, "reply not NUL-terminated");
    assert!(!frame[..n - 1].contains(&0), "NUL inside a reply");
    assert!(frame.is_ascii(), "non-ASCII reply (ensure_ascii)");
}

fuzz_target!(|data: &[u8]| {
    let mut parts: Vec<&[u8]> = data.split(|b| *b == 0).collect();
    parts.pop(); // unterminated tail: buffered, never parsed
    for msg in parts {
        match MgmtRequest::parse(msg) {
            Ok(MgmtRequest::Invalid { cmd }) => {
                check(&reply_frame(&MgmtRequest::invalid_reply(&cmd)))
            }
            Ok(MgmtRequest::Kickban { user }) => check(&reply_frame(&json!({ "user": user }))),
            Ok(_) => {}
            Err(e) => check(&reply_frame(&json!({ "error": e }))),
        }
        if let Ok(v) = serde_json::from_slice::<Value>(msg) {
            check(&reply_frame(&v));
        }
    }
});
