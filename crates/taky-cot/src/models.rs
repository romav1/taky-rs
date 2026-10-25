//! CoT models (`taky/cot/models/*.py`): [`Event`], [`Point`], [`Detail`], [`TakUser`],
//! [`TakDevice`], [`GeoChat`], [`Teams`] and the wire [`Frame`].
//!
//! Field sets follow the original. All time values are naive UTC, as in the original
//! (`tzinfo=None`): dates are parsed by [`crate::isoparse::isoparse`] (offset dropped, U001),
//! floats by [`taky_common::pyparse::py_float`] and printed with `%.6f`/`%.1f` (U002).
//!
//! S-306: [`Event`], [`Point`], [`Detail`], the parsing side of [`TakUser`]/[`GeoChat`] (needed by
//! the `<detail>` dispatch). S-307: `to_element` of field-built `TakUser`/`GeoChat`.

use std::sync::Arc;

use chrono::NaiveDateTime;
use taky_common::Clock;
use taky_common::pyfmt::{fmt_f1, fmt_f6, isoformat_ms, round_half_even};
use taky_common::pyparse::py_float;
use taky_xml::{Element, SerOpts};

use crate::isoparse::isoparse;

/// An event serialized **once** (`etree.tostring(event.as_element)`), shared by all
/// recipients: fan-out clones the `Arc`, not the bytes. The same bytes are stored in Redis.
pub type Frame = Arc<[u8]>;

/// Error turning an element into a model (`models/errors.py:UnmarshalError`).
///
/// For a stream this is not fatal: log + `log_cot(__taky_err)`, the connection stays open.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct UnmarshalError(pub String);

/// Error serializing a model (e.g. a value that cannot be represented in XML).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("serialize error: {0}")]
pub struct SerializeError(pub String);

/// `<point>` (`models/point.py`). Defaults: `0, 0, 0, 9999999.0, 9999999.0`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Point {
    /// `lat`.
    pub lat: f64,
    /// `lon`.
    pub lon: f64,
    /// `hae`.
    pub hae: f64,
    /// `ce`.
    pub ce: f64,
    /// `le`.
    pub le: f64,
}

impl Point {
    /// `Point.from_elm`: all five attributes through Python `float()`; a missing or invalid one
    /// is an error (the caller turns it into `Issue parsing point`).
    pub fn from_element(e: &Element) -> Result<Point, UnmarshalError> {
        let f = |k: &str| {
            e.get(k)
                .and_then(py_float)
                .ok_or_else(|| UnmarshalError(format!("Invalid point attribute '{k}'")))
        };
        Ok(Point {
            lat: f("lat")?,
            lon: f("lon")?,
            hae: f("hae")?,
            ce: f("ce")?,
            le: f("le")?,
        })
    }

    /// `Point.as_element`: `lat lon` as `%.6f`, `hae ce le` as `%.1f`, in that order.
    pub fn to_element(&self) -> Element {
        let mut e = Element::new("point");
        e.set("lat", fmt_f6(self.lat));
        e.set("lon", fmt_f6(self.lon));
        e.set("hae", fmt_f1(self.hae));
        e.set("ce", fmt_f1(self.ce));
        e.set("le", fmt_f1(self.le));
        e
    }
}

impl Default for Point {
    fn default() -> Self {
        Point {
            lat: 0.0,
            lon: 0.0,
            hae: 0.0,
            ce: 9_999_999.0,
            le: 9_999_999.0,
        }
    }
}

/// Generic `<detail>` (`models/detail.py`): the element is kept as-is.
#[derive(Debug, Clone, PartialEq)]
pub struct Detail {
    /// The original `<detail>` element.
    pub elm: Element,
}

impl Detail {
    /// `Detail.from_elm`.
    pub fn from_element(elm: &Element) -> Result<Detail, UnmarshalError> {
        if elm.tag != "detail" {
            return Err(UnmarshalError(format!(
                "Cannot create Detail from {}",
                elm.tag
            )));
        }
        Ok(Detail { elm: elm.clone() })
    }

    /// `Detail.has_marti`: the **first** direct `<marti>` child has at least one direct `<dest>`
    /// child (any attributes) — spec §7.2, V021.
    pub fn has_marti(&self) -> bool {
        has_marti(Some(&self.elm))
    }

    /// `Detail.marti_cs`: `callsign` of every `<dest>` of the first `<marti>`, in document order;
    /// `None` for a `<dest>` without `callsign` (Python yields `None`, the Router matches on it).
    pub fn marti_cs(&self) -> Vec<Option<String>> {
        marti_cs(Some(&self.elm))
    }
}

fn marti_cs(elm: Option<&Element>) -> Vec<Option<String>> {
    elm.and_then(|e| e.find("marti"))
        .map(|m| {
            m.child_elements()
                .filter(|d| d.tag == "dest")
                .map(|d| d.get("callsign").map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

fn has_marti(elm: Option<&Element>) -> bool {
    elm.and_then(|e| e.find("marti"))
        .is_some_and(|m| m.child_elements().any(|d| d.tag == "dest"))
}

/// `TAKUser.is_type`: the direct child tags include `takv`, `contact` and `__group`.
fn is_takuser(tags: &[&str]) -> bool {
    ["takv", "contact", "__group"]
        .iter()
        .all(|t| tags.contains(t))
}

/// `GeoChat.is_type`: the direct child tags include `__chat`, `remarks` and `link`.
fn is_geochat(tags: &[&str]) -> bool {
    ["__chat", "remarks", "link"]
        .iter()
        .all(|t| tags.contains(t))
}

/// Python `TypeError`/`ValueError` while parsing a child of `<event>`.
fn child_err(tag: &str) -> UnmarshalError {
    UnmarshalError(format!("Issue parsing {tag}"))
}

impl TakDevice {
    /// `TAKDevice.from_elm` (attributes as is).
    pub fn from_element(takv: &Element) -> TakDevice {
        let a = |k: &str| takv.get(k).map(str::to_string);
        TakDevice {
            os: a("os"),
            version: a("version"),
            device: a("device"),
            platform: a("platform"),
        }
    }
}

/// `TAKDevice` (`models/takuser.py`): `takv` attributes.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TakDevice {
    /// `takv/@os`.
    pub os: Option<String>,
    /// `takv/@version`.
    pub version: Option<String>,
    /// `takv/@device`.
    pub device: Option<String>,
    /// `takv/@platform`.
    pub platform: Option<String>,
}

/// `TAKUser` detail (`models/takuser.py`): an ATAK/WinTAK client identifying itself.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TakUser {
    /// The original `<detail>` (`None` for an object built from fields).
    pub elm: Option<Element>,
    /// Event `uid`.
    pub uid: Option<String>,
    /// `contact/@callsign`.
    pub callsign: Option<String>,
    /// Event `type` (marker).
    pub marker: Option<String>,
    /// `__group/@name` as a team.
    pub group: Option<Teams>,
    /// `__group/@role`.
    pub role: Option<String>,
    /// `contact/@phone`.
    pub phone: Option<String>,
    /// `contact/@xmppUsername`.
    pub xmpp: Option<String>,
    /// `contact/@endpoint`.
    pub endpoint: Option<String>,
    /// `track/@course` (Python `float()`).
    pub course: Option<f64>,
    /// `track/@speed` (Python `float()`).
    pub speed: Option<f64>,
    /// `status/@battery` (raw attribute text).
    pub battery: Option<String>,
    /// `takv`.
    pub device: TakDevice,
}

impl TakUser {
    /// `TAKUser.from_elm(elm, uid)`: children in document order, the last one of a tag wins.
    /// `contact/@xmppUsername` is **not** read (as in the original: `xmpp` stays `None`);
    /// an unknown or missing `__group/@name` is `Teams.UNKNOWN` = Cyan; a missing or invalid
    /// `track/@course|@speed` is an error (`float()` raises; the caller reports `Issue parsing detail`).
    pub fn from_element(detail: &Element, uid: Option<&str>) -> Result<TakUser, UnmarshalError> {
        let mut u = TakUser {
            elm: Some(detail.clone()),
            uid: uid.map(str::to_string),
            ..TakUser::default()
        };
        let a = |e: &Element, k: &str| e.get(k).map(str::to_string);
        for d in detail.child_elements() {
            match d.tag.as_str() {
                "takv" => u.device = TakDevice::from_element(d),
                "contact" => {
                    u.callsign = a(d, "callsign");
                    u.phone = a(d, "phone");
                    u.endpoint = a(d, "endpoint");
                }
                "__group" => {
                    u.group = Some(
                        d.get("name")
                            .and_then(Teams::from_name)
                            .unwrap_or(Teams::Cyan),
                    );
                    u.role = a(d, "role");
                }
                "status" => u.battery = a(d, "battery"),
                "track" => {
                    let f = |k: &str| {
                        d.get(k)
                            .and_then(py_float)
                            .ok_or_else(|| UnmarshalError(format!("Invalid track/@{k}")))
                    };
                    u.course = Some(f("course")?);
                    u.speed = Some(f("speed")?);
                }
                _ => {}
            }
        }
        Ok(u)
    }

    /// `TAKUser.as_element` — the original `<detail>` when there is one; objects built from
    /// fields (`test_takuser.test_as_element`, qa01 testkit request A.4) — S-307.
    pub fn to_element(&self) -> Element {
        match &self.elm {
            Some(e) => e.clone(),
            None => todo!("S-307: TAKUser.as_element from fields"),
        }
    }

    /// `has_marti` inherited from `Detail` (`False` without an element).
    pub fn has_marti(&self) -> bool {
        has_marti(self.elm.as_ref())
    }

    /// `marti_cs` inherited from `Detail`.
    pub fn marti_cs(&self) -> Vec<Option<String>> {
        marti_cs(self.elm.as_ref())
    }
}

/// `GeoChat` detail (`models/geochat.py`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GeoChat {
    /// The original `<detail>` (`None` for an object built from fields).
    pub elm: Option<Element>,
    /// `__chat/@chatroom`.
    pub chatroom: Option<String>,
    /// `__chat/@parent`.
    pub chat_parent: Option<String>,
    /// `__chat/@groupOwner`.
    pub group_owner: bool,
    /// `link/@uid`.
    pub src_uid: Option<String>,
    /// `__chat/@senderCallsign`.
    pub src_cs: Option<String>,
    /// `link/@type`.
    pub src_marker: Option<String>,
    /// `remarks` text.
    pub message: Option<String>,
    /// `remarks/@time`.
    pub message_ts: Option<NaiveDateTime>,
    /// Destination uid (direct message).
    pub dst_uid: Option<String>,
    /// Destination team (group chat).
    pub dst_team: Option<Teams>,
}

impl GeoChat {
    /// `chatroom == "All Chat Rooms"`.
    pub fn broadcast(&self) -> bool {
        self.chatroom.as_deref() == Some(ALL_CHAT_ROOMS)
    }

    /// `GeoChat.from_elm`. Missing `__chat`, `__chat/chatgrp`, `remarks` or `link` is the
    /// error `Detail does not contain GeoChat` (an `UnmarshalError`, not re-wrapped by the
    /// caller); an unknown team name with `parent="TeamGroups"` or a bad/missing `remarks/@time`
    /// is a Python `ValueError`/`TypeError`, reported by the caller as `Issue parsing detail`
    /// (see [`GeoChat::from_element_inner`]).
    pub fn from_element(detail: &Element) -> Result<GeoChat, UnmarshalError> {
        match GeoChat::from_element_inner(detail)? {
            Ok(g) => Ok(g),
            Err(()) => Err(child_err("detail")),
        }
    }

    /// Outer error: `UnmarshalError` raised by `from_elm` itself; inner `Err(())`: a Python
    /// `ValueError`/`TypeError`.
    fn from_element_inner(detail: &Element) -> Result<Result<GeoChat, ()>, UnmarshalError> {
        if detail.tag != "detail" {
            return Err(UnmarshalError(format!(
                "Cannot create GeoChat from {}",
                detail.tag
            )));
        }
        let chat = detail.find("__chat");
        let chatgrp = chat.and_then(|c| c.find("chatgrp"));
        let remarks = detail.find("remarks");
        let link = detail.find("link");
        let (Some(chat), Some(_), Some(remarks), Some(link)) = (chat, chatgrp, remarks, link)
        else {
            return Err(UnmarshalError("Detail does not contain GeoChat".into()));
        };
        let a = |e: &Element, k: &str| e.get(k).map(str::to_string);
        let mut g = GeoChat {
            elm: Some(detail.clone()),
            chat_parent: a(chat, "parent"),
            group_owner: chat.get("groupOwner") == Some("true"),
            src_uid: a(link, "uid"),
            src_cs: a(chat, "senderCallsign"),
            src_marker: a(link, "type"),
            chatroom: a(chat, "chatroom"),
            ..GeoChat::default()
        };
        if g.chat_parent.as_deref() == Some(CHAT_PARENT_TEAM) {
            match g.chatroom.as_deref().and_then(Teams::from_name) {
                Some(t) => g.dst_team = Some(t),
                None => return Ok(Err(())),
            }
        } else if g.chatroom.as_deref() != Some(ALL_CHAT_ROOMS) {
            g.dst_uid = a(chat, "id");
        }
        g.message = remarks.text.clone();
        match remarks.get("time").and_then(isoparse) {
            Some(t) => g.message_ts = Some(t),
            None => return Ok(Err(())),
        }
        Ok(Ok(g))
    }

    /// `GeoChat.as_element` — the original `<detail>` when there is one; objects built from
    /// fields (`test_router.test_geochat`, qa01 testkit request A.4) — S-307.
    pub fn to_element(&self) -> Element {
        match &self.elm {
            Some(e) => e.clone(),
            None => todo!("S-307: GeoChat.as_element from fields"),
        }
    }

    /// `has_marti` inherited from `Detail` (`False` without an element).
    pub fn has_marti(&self) -> bool {
        has_marti(self.elm.as_ref())
    }

    /// `marti_cs` inherited from `Detail`.
    pub fn marti_cs(&self) -> Vec<Option<String>> {
        marti_cs(self.elm.as_ref())
    }
}

/// The GeoChat broadcast room name (`geochat.py:ALL_CHAT_ROOMS`).
pub const ALL_CHAT_ROOMS: &str = "All Chat Rooms";

/// `ChatParents.TEAM` (`geochat.py`).
pub const CHAT_PARENT_TEAM: &str = "TeamGroups";

/// ATAK team colors (`models/teams.py:Teams`); the value is the `__group/@name` text.
/// `Teams.UNKNOWN` is a Python enum alias of `Cyan` and therefore has no variant here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[allow(missing_docs)]
pub enum Teams {
    White,
    Yellow,
    Orange,
    Magenta,
    Red,
    Maroon,
    Purple,
    DarkBlue,
    Blue,
    Cyan,
    Teal,
    Green,
    DarkGreen,
    Brown,
}

impl Teams {
    /// All teams in declaration order.
    pub const ALL: [Teams; 14] = [
        Teams::White,
        Teams::Yellow,
        Teams::Orange,
        Teams::Magenta,
        Teams::Red,
        Teams::Maroon,
        Teams::Purple,
        Teams::DarkBlue,
        Teams::Blue,
        Teams::Cyan,
        Teams::Teal,
        Teams::Green,
        Teams::DarkGreen,
        Teams::Brown,
    ];

    /// Wire name (`Teams.value`).
    pub fn as_str(self) -> &'static str {
        match self {
            Teams::White => "White",
            Teams::Yellow => "Yellow",
            Teams::Orange => "Orange",
            Teams::Magenta => "Magenta",
            Teams::Red => "Red",
            Teams::Maroon => "Maroon",
            Teams::Purple => "Purple",
            Teams::DarkBlue => "Dark Blue",
            Teams::Blue => "Blue",
            Teams::Cyan => "Cyan",
            Teams::Teal => "Teal",
            Teams::Green => "Green",
            Teams::DarkGreen => "Dark Green",
            Teams::Brown => "Brown",
        }
    }

    /// `Teams(value)`; `None` for an unknown name.
    pub fn from_name(name: &str) -> Option<Teams> {
        Teams::ALL.into_iter().find(|t| t.as_str() == name)
    }
}

/// The parsed `<detail>`: which model `Event.from_elm` picked (TAKUser before GeoChat).
#[derive(Debug, Clone, PartialEq)]
pub enum EventDetail {
    /// GeoChat (`b-t-f` + `__chat`).
    GeoChat(GeoChat),
    /// TAK user identification (`contact` + `takv`/`__group`).
    TakUser(TakUser),
    /// Anything else.
    Plain(Detail),
}

impl EventDetail {
    /// `detail.has_marti` (every model inherits it from `Detail`).
    pub fn has_marti(&self) -> bool {
        match self {
            EventDetail::GeoChat(g) => g.has_marti(),
            EventDetail::TakUser(u) => u.has_marti(),
            EventDetail::Plain(d) => d.has_marti(),
        }
    }

    /// `detail.marti_cs`.
    pub fn marti_cs(&self) -> Vec<Option<String>> {
        match self {
            EventDetail::GeoChat(g) => g.marti_cs(),
            EventDetail::TakUser(u) => u.marti_cs(),
            EventDetail::Plain(d) => d.marti_cs(),
        }
    }

    /// `detail.as_element` (the original element for parsed details).
    pub fn to_element(&self) -> Element {
        match self {
            EventDetail::GeoChat(g) => g.to_element(),
            EventDetail::TakUser(u) => u.to_element(),
            EventDetail::Plain(d) => d.elm.clone(),
        }
    }

    /// `Event.from_elm` detail dispatch by the set of direct child tags (`event.py:79-85`).
    fn from_element(detail: &Element, uid: Option<&str>) -> Result<EventDetail, UnmarshalError> {
        let tags: Vec<&str> = detail.child_elements().map(|c| c.tag.as_str()).collect();
        if is_takuser(&tags) {
            TakUser::from_element(detail, uid)
                .map(EventDetail::TakUser)
                .map_err(|_| child_err("detail"))
        } else if is_geochat(&tags) {
            GeoChat::from_element(detail).map(EventDetail::GeoChat)
        } else {
            Detail::from_element(detail).map(EventDetail::Plain)
        }
    }
}

/// `<event>` (`models/event.py`).
#[derive(Debug, Clone, PartialEq)]
pub struct Event {
    /// `version` (missing ⇒ `None`; B2/V013 fixed: no crash on replay).
    pub version: Option<String>,
    /// `uid`.
    pub uid: Option<String>,
    /// `type` (`etype`); `None` ⇒ the Router stops after the monitor copy.
    pub etype: Option<String>,
    /// `how`.
    pub how: Option<String>,
    /// `time` (naive UTC).
    pub time: NaiveDateTime,
    /// `start` (naive UTC).
    pub start: NaiveDateTime,
    /// `stale` (naive UTC).
    pub stale: NaiveDateTime,
    /// `<point>`.
    pub point: Point,
    /// `<detail>`, if present.
    pub detail: Option<EventDetail>,
}

impl Event {
    /// `Event.from_elm` (`event.py:47-92`), in the original order of checks:
    /// tag `event` → `time`/`start`/`stale` via `isoparse` (`Date parsing error`) → `uid` →
    /// `type` → children: `point` and `detail`, the **last** of each wins, others are ignored.
    /// No `<point>` ⇒ [`Point::default`] (V010). `version`/`how` are optional (D-8).
    pub fn from_element(e: &Element) -> Result<Event, UnmarshalError> {
        if e.tag != "event" {
            return Err(UnmarshalError(format!(
                "Cannot create Event from {}",
                e.tag
            )));
        }
        let date = |k: &str| {
            e.get(k)
                .and_then(isoparse)
                .ok_or_else(|| UnmarshalError("Date parsing error".into()))
        };
        let (time, start, stale) = (date("time")?, date("start")?, date("stale")?);
        let a = |k: &str| e.get(k).map(str::to_string);
        let mut evt = Event {
            version: a("version"),
            uid: a("uid"),
            etype: a("type"),
            how: a("how"),
            time,
            start,
            stale,
            point: Point::default(),
            detail: None,
        };
        if evt.uid.is_none() {
            return Err(UnmarshalError("Event must have 'uid' attribute".into()));
        }
        if evt.etype.is_none() {
            return Err(UnmarshalError("Event must have 'type' attribute".into()));
        }
        for child in e.child_elements() {
            match child.tag.as_str() {
                "point" => {
                    evt.point = Point::from_element(child).map_err(|_| child_err("point"))?;
                }
                "detail" => {
                    evt.detail = Some(EventDetail::from_element(child, evt.uid.as_deref())?);
                }
                _ => {}
            }
        }
        Ok(evt)
    }

    /// `Event.as_element`: attributes `version uid type how time start stale` (absent ones are
    /// omitted — Python raises there, see [`Event::to_frame`]), `<point>`, then the detail.
    ///
    /// The parsed `<detail>` is appended as lxml moves it into the new tree: its namespace
    /// declarations are reconciled ([`Element::reconcile_moved_ns`]) and its **tail is kept**
    /// (`<detail>…</detail>\n</event>` is real output).
    pub fn to_element(&self) -> Element {
        let mut e = Element::new("event");
        for (k, v) in [
            ("version", &self.version),
            ("uid", &self.uid),
            ("type", &self.etype),
            ("how", &self.how),
        ] {
            if let Some(v) = v {
                e.set(k, v.as_str());
            }
        }
        e.set("time", format!("{}Z", isoformat_ms(self.time)));
        e.set("start", format!("{}Z", isoformat_ms(self.start)));
        e.set("stale", format!("{}Z", isoformat_ms(self.stale)));
        e.append(self.point.to_element());
        if let Some(d) = &self.detail {
            let mut d = d.to_element();
            d.reconcile_moved_ns();
            e.append(d);
        }
        e
    }

    /// `etree.tostring(self.as_element)` as a shared [`Frame`].
    ///
    /// D-8: an event without `version`, `uid`, `type` or `how` cannot be serialized (Python's
    /// `elm.set(k, None)` raises `TypeError`): it is delivered to no one and not persisted.
    pub fn to_frame(&self) -> Result<Frame, SerializeError> {
        for (k, v) in [
            ("version", &self.version),
            ("uid", &self.uid),
            ("type", &self.etype),
            ("how", &self.how),
        ] {
            if v.is_none() {
                return Err(SerializeError(format!("event has no '{k}' attribute")));
            }
        }
        Ok(taky_xml::serialize(&self.to_element(), &SerOpts::default()).into())
    }

    /// `Event.persist_ttl`: `round((stale - utcnow()).total_seconds())` (half-even),
    /// with "now" taken from the injected clock (truncated to microseconds, like `utcnow()`).
    pub fn persist_ttl(&self, clock: &dyn Clock) -> i64 {
        let us = |t: NaiveDateTime| {
            let t = t.and_utc();
            i128::from(t.timestamp()) * 1_000_000 + i128::from(t.timestamp_subsec_micros())
        };
        let delta = us(self.stale) - us(clock.utc_now());
        // timedelta.total_seconds() = microseconds / 10**6 (one correctly rounded division).
        round_half_even(delta as f64 / 1e6)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn teams_round_trip() {
        for t in Teams::ALL {
            assert_eq!(Teams::from_name(t.as_str()), Some(t));
        }
        assert_eq!(Teams::from_name("Dark Blue"), Some(Teams::DarkBlue));
        assert_eq!(Teams::from_name("dark blue"), None);
    }

    #[test]
    fn point_defaults_and_broadcast() {
        let p = Point::default();
        assert_eq!((p.ce, p.le), (9_999_999.0, 9_999_999.0));
        let g = GeoChat {
            chatroom: Some(ALL_CHAT_ROOMS.into()),
            ..GeoChat::default()
        };
        assert!(g.broadcast());
        assert!(!GeoChat::default().broadcast());
    }
}
