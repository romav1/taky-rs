"""Generate models_from_fields.json: field-built TAKUser/GeoChat/TAKDevice `as_element` serialized
by lxml (`etree.tostring`), or an error marker where Python raises.

Run from taky-rs/:  PYTHONPATH=../taky python -B crates/taky-cot/tests/fixtures/gen_models.py
Floats are given as Python `repr` strings, datetimes as `isoformat()` (naive).
"""
import json
import os
import random
from datetime import datetime, timedelta

from lxml import etree

from taky.cot import models

STRS = [None, "", "x", "JENNY", "*:-1:stcp", "a b&c<d>\"'", "üß中", "\U0001f600",
        "tab\tnl\ncr\r", "bad\x01", "￾", "\x7f\x85", "All Chat Rooms", "Cyan", "Dark Blue",
        "TeamGroups", "RootContactGroup", "  ", "]]>"]
FLOATS = [None, 0.0, -0.0, 1.0, 90.1, 10.3, 0.05, 0.25, 0.35, -1.45, 1e20, 123456.789,
          float("nan"), float("inf"), float("-inf"), 2.675, 1e-7]
TEAMS = [None] + [t.value for t in models.Teams]


def fs(v):
    return None if v is None else repr(v)


def run(fn):
    try:
        return {"out": etree.tostring(fn()).decode("ascii")}
    except (ValueError, TypeError, AttributeError) as exc:
        return {"err": type(exc).__name__}


def takuser_case(rnd, fixed=None):
    f = fixed or {
        "callsign": rnd.choice(STRS), "group": rnd.choice(TEAMS), "role": rnd.choice(STRS),
        "phone": rnd.choice(STRS), "xmpp": rnd.choice(STRS), "endpoint": rnd.choice(STRS),
        "course": rnd.choice(FLOATS), "speed": rnd.choice(FLOATS), "battery": rnd.choice(STRS),
        "os": rnd.choice(STRS), "version": rnd.choice(STRS), "device": rnd.choice(STRS),
        "platform": rnd.choice(STRS),
    }
    # bias towards valid required fields so most cases produce XML
    if not fixed and rnd.random() < 0.7:
        for k in ("callsign", "role", "endpoint"):
            if f[k] is None or "\x01" in f[k] or "￾" in f[k]:
                f[k] = "ok-" + k
        f["group"] = f["group"] or "Cyan"
    u = models.TAKUser(None)
    for k in ("callsign", "role", "phone", "xmpp", "endpoint", "course", "speed", "battery"):
        setattr(u, k, f[k])
    u.group = None if f["group"] is None else models.Teams(f["group"])
    u.device = models.TAKDevice(os=f["os"], version=f["version"], device=f["device"],
                                platform=f["platform"])
    res = run(lambda: u.as_element)
    out = dict(f, course=fs(f["course"]), speed=fs(f["speed"]))
    out.update(res)
    return out


def geochat_case(rnd):
    f = {
        "chatroom": rnd.choice(STRS), "chat_parent": rnd.choice(STRS),
        "group_owner": rnd.random() < 0.5, "src_uid": rnd.choice(STRS), "src_cs": rnd.choice(STRS),
        "src_marker": rnd.choice(STRS), "message": rnd.choice(STRS),
        "message_ts": rnd.choice([None, datetime(2021, 2, 23, 22, 28, 22, 191000),
                                  datetime(2021, 1, 1) + timedelta(microseconds=rnd.randrange(10**13))]),
        "dst_uid": rnd.choice(STRS), "dst_team": rnd.choice(TEAMS),
    }
    if rnd.random() < 0.7:
        for k in ("chat_parent", "src_uid", "src_cs", "src_marker", "dst_uid"):
            if f[k] is None or "\x01" in f[k] or "￾" in f[k]:
                f[k] = "ok-" + k
        if f["chatroom"] is None or "\x01" in f["chatroom"] or "￾" in f["chatroom"]:
            f["chatroom"] = "All Chat Rooms"
        if f["message"] is not None and ("\x01" in f["message"] or "￾" in f["message"]):
            f["message"] = "ok"
        f["message_ts"] = f["message_ts"] or datetime(2021, 2, 23, 22, 28, 22, 191000)
    g = models.GeoChat(None)
    for k, v in f.items():
        if k != "dst_team":
            setattr(g, k, v)
    g.dst_team = None if f["dst_team"] is None else models.Teams(f["dst_team"])
    res = run(lambda: g.as_element)
    out = dict(f, message_ts=None if f["message_ts"] is None else f["message_ts"].isoformat())
    out.update(res)
    return out


def main():
    rnd = random.Random(307)
    jenny = {"callsign": "JENNY", "group": "Cyan", "role": "Team Member", "phone": "800-867-5309",
             "xmpp": None, "endpoint": "*:-1:stcp", "course": 90.1, "speed": 10.3, "battery": "83",
             "os": "Android", "version": "10", "device": "Some Device", "platform": "python unittest"}
    data = {
        "takuser": [takuser_case(rnd, jenny)] + [takuser_case(rnd) for _ in range(300)],
        "geochat": [geochat_case(rnd) for _ in range(300)],
    }
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models_from_fields.json")
    with open(path, "w", encoding="utf-8") as fh:
        # one case per line (diff-friendly)
        fh.write("{\n")
        for i, (k, cases) in enumerate(data.items()):
            fh.write(' "%s": [\n' % k)
            fh.write(",\n".join(json.dumps(c, separators=(",", ":")) for c in cases))
            fh.write("\n ]%s\n" % ("," if i + 1 < len(data) else ""))
        fh.write("}\n")
    for k, v in data.items():
        print(k, len(v), "errors:", sum("err" in c for c in v))


main()
