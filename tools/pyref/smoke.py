"""Smoke test for the Python taky reference bench (run by smoke.sh inside the bench venv).

Checks:
  1. CoT broadcast: two TLS clients (certs from build_client) connect to taky; the SA event sent
     by alpha is delivered to bravo byte-for-byte (the server re-serializes, so we compare the uid
     and the callsign, and that bravo does not get its own event echoed).
  2. mgmt socket answers {"cmd": "ping"}.
  3. taky_dps answers GET /Marti/api/version over TLS with a client certificate (HTTP 200).
Exit 0 = PASS.
"""

import datetime as dt
import json
import socket
import ssl
import sys
import time

from lxml import etree


def now(offset=0):
    t = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=offset)
    return t.strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def sa_event(uid, callsign):
    return (
        f'<event version="2.0" uid="{uid}" type="a-f-G-U-C" how="m-g" '
        f'time="{now()}" start="{now()}" stale="{now(120)}">'
        '<point lat="10.0" lon="20.0" hae="0" ce="9999999" le="9999999"/>'
        f'<detail><contact callsign="{callsign}" endpoint="*:-1:stcp"/>'
        '<__group name="Cyan" role="Team Member"/>'
        '<takv device="pyref" platform="pyref-smoke" os="linux" version="0"/></detail></event>'
    ).encode()


def tls_ctx(state, name):
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=f"{state}/site/ssl/ca.crt")
    ctx.check_hostname = False  # server cert CN is pyref.local, we dial an IP; the chain is verified
    ctx.load_cert_chain(f"{state}/clients/{name}.crt", f"{state}/clients/{name}.key")
    return ctx


def connect(state, name, host, port):
    raw = socket.create_connection((host, port), timeout=5)
    return tls_ctx(state, name).wrap_socket(raw)


def read_events(sock, until_uid, timeout):
    """Read and split events until an event with until_uid arrives or timeout; returns all events."""
    buf, events, deadline = b"", [], time.monotonic() + timeout
    while time.monotonic() < deadline:
        sock.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            chunk = sock.recv(65536)
        except (socket.timeout, TimeoutError):
            break
        if not chunk:
            break
        buf += chunk
        while b"</event>" in buf:
            evt, buf = buf.split(b"</event>", 1)
            start = evt.find(b"<event")
            events.append(etree.fromstring(evt[start:] + b"</event>"))
        if any(e.get("uid") == until_uid for e in events):
            break
    return events


def main(state, host, cot_port, dps_port):
    failures = []

    # 1. CoT broadcast
    bravo = connect(state, "pyref-bravo", host, cot_port)
    bravo.sendall(sa_event("pyref-bravo-uid", "BRAVO"))
    time.sleep(0.3)
    alpha = connect(state, "pyref-alpha", host, cot_port)
    alpha.sendall(sa_event("pyref-alpha-uid", "ALPHA"))
    got = read_events(bravo, "pyref-alpha-uid", timeout=5)
    hit = [e for e in got if e.get("uid") == "pyref-alpha-uid"]
    if not hit:
        failures.append(f"bravo did not receive alpha's SA (got uids {[e.get('uid') for e in got]})")
    else:
        cs = hit[0].find("detail/contact")
        callsign = cs.get("callsign") if cs is not None else None
        if callsign != "ALPHA":
            failures.append(f"broadcast callsign mismatch: {callsign!r}")
        else:
            print(f"[smoke] PASS cot broadcast: alpha -> bravo ({len(got)} event(s) read by bravo)")
    if any(e.get("uid") == "pyref-bravo-uid" for e in got):
        failures.append("bravo received its own event back")
    alpha.close()
    bravo.close()

    # 2. mgmt ping
    mgmt = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    mgmt.settimeout(3)
    try:
        mgmt.connect(f"{state}/site/taky-mgmt.sock")
        mgmt.sendall(b'{"cmd": "ping"}\0')
        resp = b""
        while not resp.endswith(b"\0"):
            chunk = mgmt.recv(4096)
            if not chunk:
                break
            resp += chunk
        obj = json.loads(resp.rstrip(b"\0"))
        print(f"[smoke] PASS mgmt ping: {obj}")
    except (OSError, ValueError) as exc:
        failures.append(f"mgmt ping failed: {exc}")
    finally:
        mgmt.close()

    # 3. DPS over TLS
    try:
        dps = connect(state, "pyref-alpha", host, dps_port)
        dps.sendall(b"GET /Marti/api/version HTTP/1.1\r\nHost: pyref\r\nConnection: close\r\n\r\n")
        resp = b""
        dps.settimeout(5)
        while True:
            chunk = dps.recv(65536)
            if not chunk:
                break
            resp += chunk
        dps.close()
        status = resp.split(b"\r\n", 1)[0].decode(errors="replace")
        body = resp.split(b"\r\n\r\n", 1)[-1][:80]
        if " 200 " not in status + " ":
            failures.append(f"DPS /Marti/api/version: {status}")
        else:
            print(f"[smoke] PASS dps version: {status} {body!r}")
    except OSError as exc:
        failures.append(f"DPS request failed: {exc}")

    for f in failures:
        print(f"[smoke] FAIL {f}")
    print("[smoke] RESULT:", "PASS" if not failures else f"FAIL ({len(failures)})")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])))
