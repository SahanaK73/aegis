"""CLI: run the collector, or verify its audit chain.

  python -m collector.main run --scenario cpu_spike --ticks 30
  python -m collector.main verify-audit
"""

from __future__ import annotations

import argparse
import sys
import time

from .config import Config
from .pipeline import Collector
from .sender import Sender
from .simulator import SCENARIOS, stream
from .store import Store


def run(cfg: Config, scenario: str, ticks: int | None, seed: int) -> int:
    store = Store(cfg.db_path)
    collector = Collector(cfg, store)
    sender = Sender(cfg, store)
    source = stream(scenario, seed)
    last_hb = 0.0
    n = 0
    print(f"collector {cfg.collector_id} -> {cfg.endpoint} scenario={scenario}", flush=True)
    try:
        while ticks is None or n < ticks:
            for record in next(source):
                collector.ingest(record)
            collector.tick()
            now = time.time()
            if now - last_hb >= cfg.heartbeat_seconds:
                collector.heartbeat(sender.consecutive_failures)
                last_hb = now
            res = sender.drain()
            n += 1
            print(
                f"tick={n} sent={res['sent']} failed={res['failed']} backlog={store.backlog()} "
                f"blocked={collector.stats['blocked']}",
                flush=True,
            )
            time.sleep(cfg.tick_seconds)
    except KeyboardInterrupt:
        pass
    finally:
        store.close()
    return 0


def verify(cfg: Config) -> int:
    store = Store(cfg.db_path)
    ok, bad = store.verify_audit_chain()
    print("audit chain OK" if ok else f"audit chain BROKEN at record id {bad}")
    store.close()
    return 0 if ok else 1


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="collector")
    sub = p.add_subparsers(dest="cmd", required=True)
    r = sub.add_parser("run")
    r.add_argument("--scenario", choices=SCENARIOS, default="normal")
    r.add_argument("--ticks", type=int, default=None, help="stop after N ticks (default: run forever)")
    r.add_argument("--seed", type=int, default=7)
    sub.add_parser("verify-audit")
    args = p.parse_args(argv)
    cfg = Config.from_env()
    if args.cmd == "run":
        return run(cfg, args.scenario, args.ticks, args.seed)
    return verify(cfg)


if __name__ == "__main__":
    sys.exit(main())
