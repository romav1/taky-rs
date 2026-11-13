//! Test prerequisites (S-802, ub01 P0-1): the one place that decides what a test does when an
//! external tool it needs is missing.
//!
//! * prerequisite available → the test runs;
//! * missing and `TAKY_REQUIRE_<KIND>` (or `TAKY_REQUIRE_ALL`) is set → **panic** with the reason,
//!   so CI that provides the tool can never go green without running the test;
//! * missing and not required → one line `SKIP(<KIND>) <test>: <reason>` on stderr and the test
//!   returns (local runs without Redis / OpenSSL / the Python original stay green).
//!
//! A variable counts as set when it is non-empty and not `0` (e.g. `TAKY_REQUIRE_REDIS=1`).
//!
//! Not behind the `testkit` feature on purpose: `takyctl` tests use it and have no `testkit`
//! dev-dependency; the module is a few pure functions that no binary calls.

use std::ffi::OsString;
use std::fmt;

/// Kind of external prerequisite of a test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Prereq {
    /// The Python original (`../taky`) and a Python with its deps (`tools/pyref/venv.sh`).
    Pyref,
    /// A `redis-server` binary on `PATH`.
    Redis,
    /// The `openssl` CLI on `PATH`.
    Openssl,
}

impl Prereq {
    /// Upper-case name used in the env variable and the SKIP line.
    pub fn name(self) -> &'static str {
        match self {
            Prereq::Pyref => "PYREF",
            Prereq::Redis => "REDIS",
            Prereq::Openssl => "OPENSSL",
        }
    }
}

impl fmt::Display for Prereq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Verdict {
    Run,
    Skip,
    Fail,
}

fn is_set(v: Option<OsString>) -> bool {
    v.is_some_and(|v| !v.is_empty() && v != "0")
}

fn verdict(kind: Prereq, available: bool, env: &dyn Fn(&str) -> Option<OsString>) -> Verdict {
    if available {
        Verdict::Run
    } else if is_set(env(&format!("TAKY_REQUIRE_{kind}"))) || is_set(env("TAKY_REQUIRE_ALL")) {
        Verdict::Fail
    } else {
        Verdict::Skip
    }
}

#[track_caller]
fn require_in<T>(
    kind: Prereq,
    value: Option<T>,
    test: &str,
    reason: &str,
    env: &dyn Fn(&str) -> Option<OsString>,
) -> Option<T> {
    match verdict(kind, value.is_some(), env) {
        Verdict::Run => value,
        Verdict::Skip => {
            eprintln!("SKIP({kind}) {test}: {reason}");
            None
        }
        Verdict::Fail => panic!(
            "{test}: prerequisite {kind} missing ({reason}) and TAKY_REQUIRE_{kind} / \
             TAKY_REQUIRE_ALL is set"
        ),
    }
}

/// `value` when the prerequisite is there (`Some`); otherwise skip (`None`) or panic, see the
/// module docs. Use: `let Some(py) = require(Prereq::Pyref, find_python(), "t", "why") else { return };`
#[track_caller]
pub fn require<T>(kind: Prereq, value: Option<T>, test: &str, reason: &str) -> Option<T> {
    require_in(kind, value, test, reason, &|k| std::env::var_os(k))
}

/// `true` when the test should go on. Use: `if !prereq(Prereq::Openssl, have, "t", "why") { return; }`
#[track_caller]
#[must_use]
pub fn prereq(kind: Prereq, available: bool, test: &str, reason: &str) -> bool {
    require(kind, available.then_some(()), test, reason).is_some()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env_of(vars: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<OsString> {
        move |k| {
            vars.iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| OsString::from(v))
        }
    }

    #[test]
    fn available_always_runs_even_when_required() {
        let env = env_of(&[("TAKY_REQUIRE_ALL", "1"), ("TAKY_REQUIRE_REDIS", "1")]);
        assert_eq!(verdict(Prereq::Redis, true, &env), Verdict::Run);
        assert_eq!(require_in(Prereq::Redis, Some(7), "t", "r", &env), Some(7));
    }

    #[test]
    fn missing_and_not_required_skips() {
        for vars in [
            &[][..],
            &[("TAKY_REQUIRE_REDIS", "0")],
            &[("TAKY_REQUIRE_REDIS", "")],
            &[("TAKY_REQUIRE_PYREF", "1")], // another kind
        ] {
            let vars: &'static [(&str, &str)] = vars;
            let env = env_of(vars);
            assert_eq!(
                verdict(Prereq::Redis, false, &env),
                Verdict::Skip,
                "{vars:?}"
            );
            assert_eq!(require_in::<()>(Prereq::Redis, None, "t", "r", &env), None);
        }
    }

    #[test]
    fn missing_and_required_fails_per_kind_and_all() {
        for kind in [Prereq::Pyref, Prereq::Redis, Prereq::Openssl] {
            let own: &'static [(&str, &str)] = match kind {
                Prereq::Pyref => &[("TAKY_REQUIRE_PYREF", "1")],
                Prereq::Redis => &[("TAKY_REQUIRE_REDIS", "1")],
                Prereq::Openssl => &[("TAKY_REQUIRE_OPENSSL", "1")],
            };
            assert_eq!(verdict(kind, false, &env_of(own)), Verdict::Fail);
            let all = env_of(&[("TAKY_REQUIRE_ALL", "1")]);
            assert_eq!(verdict(kind, false, &all), Verdict::Fail);
        }
    }

    #[test]
    #[should_panic(expected = "my_test: prerequisite OPENSSL missing (no openssl on PATH)")]
    fn required_panics_with_test_and_reason() {
        let env = env_of(&[("TAKY_REQUIRE_OPENSSL", "yes")]);
        let _ = require_in::<()>(Prereq::Openssl, None, "my_test", "no openssl on PATH", &env);
    }
}
