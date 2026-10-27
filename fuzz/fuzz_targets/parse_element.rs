//! `parse_element` (S-407): the whole-document parser used for Redis values (`persist.rs`, stream
//! limits) and DPS `/Marti/vcm` (D-1). Invariants: no panic; an accepted document serializes with
//! every `SerOpts` combination in use and `Event::from_element` does not panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use taky_xml::{Limits, SerOpts, parse_element, serialize};

fuzz_target!(|data: &[u8]| {
    let Ok(e) = parse_element(data, &Limits::DEFAULT) else {
        return;
    };
    for o in [
        SerOpts::default(),
        SerOpts {
            pretty_print: true,
            ..SerOpts::default()
        },
        SerOpts {
            xml_declaration: true,
            ..SerOpts::default()
        },
        SerOpts {
            xml_declaration: true,
            standalone: Some(true),
            pretty_print: true,
            ..SerOpts::default()
        },
        SerOpts {
            with_tail: false,
            ..SerOpts::default()
        },
    ] {
        let _ = serialize(&e, &o);
    }
    if let Ok(evt) = taky_cot::Event::from_element(&e) {
        let _ = evt.to_frame();
    }
});
