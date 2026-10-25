//! U001 (isoparse) and U002 (float + `%.6f`/`%.1f`) — an01 unit vectors, run through the public
//! model API (`Event::from_element` / `Point::from_element`) as well as the helpers.
#![allow(clippy::unwrap_used)] // test helpers outside #[test] fns

use serde_json::Value;
use taky_common::pyfmt::{fmt_f1, fmt_f6, isoformat_ms};
use taky_common::pyparse::py_float;
use taky_common::vectors::read_vector;
use taky_cot::isoparse::isoparse;
use taky_cot::{Event, Point};
use taky_xml::Element;

fn cases(id: &str) -> Vec<Value> {
    let v: Value = serde_json::from_str(&read_vector(&format!("unit/{id}.json"))).unwrap();
    v["cases"].as_array().unwrap().clone()
}

fn event_with_time(t: Option<&str>) -> Element {
    let mut e = Element::new("event");
    for (k, v) in [
        ("version", "2.0"),
        ("uid", "U"),
        ("type", "a"),
        ("how", "h"),
    ] {
        e.set(k, v);
    }
    if let Some(t) = t {
        e.set("time", t);
    }
    e.set("start", "2030-01-01T00:00:00Z");
    e.set("stale", "2030-01-01T00:00:00Z");
    e
}

#[test]
fn u001_isoparse() {
    let cases = cases("U001");
    assert_eq!(cases.len(), 40);
    for c in &cases {
        let input = c["input"].as_str();
        let exp = &c["expect"];
        let got = input.and_then(isoparse);
        let evt = Event::from_element(&event_with_time(input));
        match exp.get("ok").and_then(Value::as_str) {
            Some(ok) => {
                let t = got.unwrap_or_else(|| panic!("{input:?}: expected {ok}"));
                assert_eq!(
                    t.format("%Y-%m-%dT%H:%M:%S%.6f").to_string(),
                    ok,
                    "{input:?}"
                );
                let cot = exp["cot"].as_str().unwrap();
                assert_eq!(format!("{}Z", isoformat_ms(t)), cot, "{input:?}");
                let elm = evt.unwrap().to_element();
                assert_eq!(elm.get("time"), Some(cot), "{input:?}");
            }
            None => {
                assert_eq!(exp["error"], "UnmarshalError");
                assert_eq!(got, None, "{input:?}");
                assert_eq!(evt.unwrap_err().0, "Date parsing error", "{input:?}");
            }
        }
    }
}

#[test]
fn u002_float() {
    let cases = cases("U002");
    assert_eq!(cases.len(), 41);
    for c in &cases {
        let input = c["input"].as_str();
        let exp = &c["expect"];
        let got = input.and_then(py_float);
        let mut pe = Element::new("point");
        for k in ["lat", "lon", "hae", "ce", "le"] {
            if let Some(i) = input {
                pe.set(k, i);
            }
        }
        let point = Point::from_element(&pe);
        match exp.get("ok").and_then(Value::as_str) {
            Some(ok) => {
                let x = got.unwrap_or_else(|| panic!("{input:?}: expected {ok}"));
                let want: f64 = ok.parse().unwrap();
                if want.is_nan() {
                    assert!(x.is_nan(), "{input:?}");
                } else {
                    assert_eq!(x.to_bits(), want.to_bits(), "{input:?}");
                }
                let (f6, f1) = (exp["f6"].as_str().unwrap(), exp["f1"].as_str().unwrap());
                assert_eq!(fmt_f6(x), f6, "{input:?}");
                assert_eq!(fmt_f1(x), f1, "{input:?}");
                let pel = point.unwrap().to_element();
                let attrs: Vec<&str> = pel.attrs.iter().map(|(_, v)| v.as_str()).collect();
                assert_eq!(attrs, [f6, f6, f1, f1, f1], "{input:?}");
            }
            None => {
                assert_eq!(exp["error"], "UnmarshalError");
                assert_eq!(got, None, "{input:?}");
                assert!(point.is_err(), "{input:?}");
            }
        }
    }
}
