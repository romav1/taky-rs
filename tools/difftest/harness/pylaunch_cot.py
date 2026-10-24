#!/usr/bin/env python3
"""
Live launcher for the ORIGINAL Python taky CoT server (difftest "py" target).

Runs `taky.cot.COTServer` as its own process (real sockets on the bench bind_ip), exactly like
`python -m taky.cot` (taky/taky/cot/__main__.py: load_config -> sock_setup -> loop() until SIGTERM,
an unhandled exception in loop() -> exit 1), plus the black-box test hooks a live difftest needs:

  * frozen clock: datetime.utcnow / time.time inside taky modules = the vector's "now" (+ advance).
    The clock objects are imported from an01's runner (shared/spec/vectors/tools/run_python.py),
    so the live process and the in-process oracle runner share one clock implementation.
  * control channel: the harness writes <ctl>/cmd.json and sends SIGUSR1; the command is executed
    in the main loop between two loop() iterations and acknowledged in <ctl>/ack.json:
        {"seq": n, "advance": seconds}  -> clock += seconds, one loop() (prune) runs, then ack
        {"seq": n, "persist": true}     -> ack carries the persistence snapshot (memory: sorted uids)
  * <ctl>/ready after sock_setup(); <ctl>/crash.txt ("Type: message") and
    <ctl>/persist-at-exit.json (post-mortem persist snapshot) if loop() raised.

The Rust target must offer the same hooks (frozen clock + advance, persist snapshot) through its
testkit feature; see qa01/handoff/T-11.md.
"""
import sys

sys.dont_write_bytecode = True  # never write __pycache__ into the read-only taky/ checkout

import argparse  # noqa: E402
import json  # noqa: E402
import logging  # noqa: E402
import os  # noqa: E402
import signal  # noqa: E402


def atomic_write(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf8") as fp:
        fp.write(data)
    os.replace(tmp, path)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--conf", required=True)
    ap.add_argument("--now", required=True)
    ap.add_argument("--ctl", required=True)
    ap.add_argument("--log-level", default="info")
    args = ap.parse_args()
    logging.basicConfig(level=args.log_level.upper(), stream=sys.stderr)

    import run_python as rp  # an01's runner: Clock, FrozenDT, FakeTimeModule, FastSelect

    from taky.config import load_config

    load_config(args.conf)

    import taky.cot.client as m_client
    import taky.cot.mgmt as m_mgmt
    import taky.cot.models.event as m_event
    import taky.cot.persistence as m_persist
    import taky.cot.router as m_router
    import taky.cot.server as m_server

    # same patch set as run_python.Runner.start()
    for mod in (m_event, m_router, m_persist, m_client):
        mod.dt = rp.FrozenDT
    for mod in (m_server, m_client, m_router, m_mgmt):
        mod.time = rp.FakeTimeModule()
    m_server.select = rp.FAST_SELECT  # select() timeout 20 ms: hooks and prune react quickly
    rp.CLOCK.set_now(args.now)

    state = {"stop": False, "ctl": False}
    signal.signal(signal.SIGTERM, lambda *_: state.update(stop=True))
    signal.signal(signal.SIGUSR1, lambda *_: state.update(ctl=True))

    from taky.cot import COTServer

    srv = COTServer()
    try:
        srv.sock_setup()
    except Exception as exc:  # pylint: disable=broad-except
        logging.error("Unable to start COTServer: %s", exc)
        srv.shutdown()
        sys.exit(1)
    atomic_write(os.path.join(args.ctl, "ready"), str(os.getpid()))

    def persist_snapshot():
        p = srv.router.persist
        if p.__class__.__name__ == "RedisPersistence":
            return {"backend": "redis"}  # harness dumps Redis itself (black box)
        return {"backend": "memory", "uids": sorted(p.events.keys())}

    def handle_ctl():
        with open(os.path.join(args.ctl, "cmd.json"), encoding="utf8") as fp:
            cmd = json.load(fp)
        ack = {"seq": cmd["seq"]}
        if "advance" in cmd:
            rp.CLOCK.offset += float(cmd["advance"])
            srv.loop()  # one iteration: router.prune() + handshake prune at the new time
        if cmd.get("persist"):
            ack["persist"] = persist_snapshot()
        atomic_write(os.path.join(args.ctl, "ack.json"), json.dumps(ack))

    ret = 0
    try:
        while not state["stop"]:
            srv.loop()
            if state["ctl"]:
                state["ctl"] = False
                handle_ctl()
    except Exception as exc:  # pylint: disable=broad-except
        logging.critical("Unhandled exception", exc_info=exc)
        atomic_write(os.path.join(args.ctl, "crash.txt"), f"{type(exc).__name__}: {exc}")
        # post-mortem hook: persistence state at the crash (the in-process oracle can still read it)
        atomic_write(os.path.join(args.ctl, "persist-at-exit.json"), json.dumps(persist_snapshot()))
        ret = 1
    try:
        srv.shutdown()
    except Exception as exc:  # pylint: disable=broad-except
        logging.critical("Exception during shutdown", exc_info=exc)
        ret = 1
    sys.exit(ret)


if __name__ == "__main__":
    main()
