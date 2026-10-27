//! `cot_decoder_stream` (S-407, test-strategy §1.6): input bytes + chunk split derived from the
//! first bytes (`taky_fuzz_common::split_chunks`) → `CotDecoder` as `conn::read_half` drives it.
//! Invariants: no panic; events ≤ `</event` + `/>`; no events after an error (poisoned decoder);
//! every server frame re-parses as one `<event>`.
#![no_main]
use libfuzzer_sys::fuzz_target;
use taky_fuzz_common::{check_stream_invariants, run_stream, split_chunks};

fuzz_target!(|data: &[u8]| {
    let chunks = split_chunks(data);
    let dump = run_stream(&chunks);
    check_stream_invariants(&chunks, &dump);
});
