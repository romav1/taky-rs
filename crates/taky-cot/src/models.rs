//! CoT models (`taky/cot/models/*.py`): [`Event`], [`Point`], [`Detail`], [`TakUser`],
//! [`TakDevice`], [`GeoChat`], [`Teams`] and the wire [`Frame`].
//!
//! Field sets follow the original; types may be refined in S-303 (by inbox agreement if a
//! public field changes). All time values are naive UTC, as in the original (`tzinfo=None`).

use std::sync::Arc;

use chrono::NaiveDateTime;
use taky_common::Clock;
use taky_xml::Element;

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
    /// `Detail.has_marti`: the detail contains `marti/dest[@callsign]`.
    pub fn has_marti(&self) -> bool {
        todo!("S-303")
    }

    /// `Detail.marti_cs`: callsigns from `marti/dest/@callsign`, in document order.
    pub fn marti_cs(&self) -> Vec<String> {
        todo!("S-303")
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
    /// `track/@course` (raw attribute text).
    pub course: Option<String>,
    /// `track/@speed` (raw attribute text).
    pub speed: Option<String>,
    /// `status/@battery` (raw attribute text).
    pub battery: Option<String>,
    /// `takv`.
    pub device: TakDevice,
}

impl TakUser {
    /// `TAKUser.from_elm(elm, uid)`.
    pub fn from_element(detail: &Element, uid: Option<&str>) -> Result<TakUser, UnmarshalError> {
        let _ = (detail, uid);
        todo!("S-303")
    }

    /// `TAKUser.as_element` — also for objects built from fields
    /// (`test_takuser.test_as_element`, qa01 testkit request A.4).
    pub fn to_element(&self) -> Element {
        todo!("S-303")
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

    /// `GeoChat.from_elm`.
    pub fn from_element(detail: &Element) -> Result<GeoChat, UnmarshalError> {
        let _ = detail;
        todo!("S-303")
    }

    /// `GeoChat.as_element` — also for objects built from fields
    /// (`test_router.test_geochat`, qa01 testkit request A.4).
    pub fn to_element(&self) -> Element {
        todo!("S-303")
    }
}

/// The GeoChat broadcast room name (`geochat.py:ALL_CHAT_ROOMS`).
pub const ALL_CHAT_ROOMS: &str = "All Chat Rooms";

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

/// The parsed `<detail>`: which model `Detail.from_elm` picked.
#[derive(Debug, Clone, PartialEq)]
pub enum EventDetail {
    /// GeoChat (`b-t-f` + `__chat`).
    GeoChat(GeoChat),
    /// TAK user identification (`contact` + `takv`/`__group`).
    TakUser(TakUser),
    /// Anything else.
    Plain(Detail),
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
    /// `Event.from_elm` (dates via `isoparse`, `point`, `detail` dispatch).
    pub fn from_element(e: &Element) -> Result<Event, UnmarshalError> {
        let _ = e;
        todo!("S-303")
    }

    /// `Event.as_element`.
    pub fn to_element(&self) -> Element {
        todo!("S-303")
    }

    /// `etree.tostring(self.as_element)` as a shared [`Frame`].
    pub fn to_frame(&self) -> Result<Frame, SerializeError> {
        todo!("S-303")
    }

    /// `Event.persist_ttl`: `round((stale - utcnow()).total_seconds())` (half-even),
    /// with "now" taken from the injected clock.
    pub fn persist_ttl(&self, clock: &dyn Clock) -> i64 {
        let _ = clock;
        todo!("S-303")
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
