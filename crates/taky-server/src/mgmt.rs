//! Management socket protocol (`taky/cot/mgmt.py`): `{"cmd": ...}\0` → JSON reply `\0`.
//! Fixes B3/V046 (mgmt does not silence traffic) and B4/V051 (`[]` does not crash).

/// A decoded mgmt request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MgmtRequest {
    /// `{"cmd": "status"}` → `uptime`, `num_clients`, `clients[]`.
    Status,
    /// `{"cmd": "ping"}` → `{"pong": "taky"}` (answered without the Router).
    Ping,
    /// `{"cmd": "kickban", "user": ...}` → `{"revoked_sns": [int...]}` (big integers).
    Kickban {
        /// CN to revoke (`None` if the key is missing/null).
        user: Option<String>,
    },
    /// Anything else → `{"error": "Invalid cmd: <cmd>"}`; `cmd` is the Python `str()` of the value.
    Invalid {
        /// Rendered `msg.get('cmd')`.
        cmd: String,
    },
}

impl MgmtRequest {
    /// Decode one message (without the trailing NUL). `Err` carries the text for
    /// `{"error": "<exc>"}` (UTF-8 / JSON errors).
    pub fn parse(msg: &[u8]) -> Result<MgmtRequest, String> {
        let _ = msg;
        todo!("dev02: S-313")
    }
}
