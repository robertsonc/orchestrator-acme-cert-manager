"""Command-line entry point: list / issue / deploy / restart / renew / renew-all."""
from __future__ import annotations

import argparse
import logging
import os
import sys

from . import config


def _setup_logging() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO"),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def cmd_list(_: argparse.Namespace) -> int:
    servers = config.load_servers()
    if not servers:
        print("No servers configured. Add entries to servers.json.")
        return 0
    for s in servers:
        latest = __import__("app.store", fromlist=["latest_for"]).latest_for(s.id)
        status = latest["outcome"] if latest else "never run"
        print(f"  {s.id:<16} {s.domain:<36} CA={s.acme_ca:<16} last={status}")
    return 0


def _renew_one(args: argparse.Namespace) -> int:
    from . import renew
    server = config.get_server(args.server_id)
    rec = renew.renew_server(server, force=args.force)
    print(f"{server.id}: {rec.outcome}")
    return 0 if rec.outcome == "success" else 1


def cmd_renew_all(args: argparse.Namespace) -> int:
    from . import renew
    records = renew.renew_all(force=args.force)
    failed = [r for r in records if r.outcome == "failed"]
    return 1 if failed else 0


def _single_step(args: argparse.Namespace, module: str, fn: str) -> int:
    mod = __import__(f"app.{module}", fromlist=[fn])
    server = config.get_server(args.server_id)
    result = getattr(mod, fn)(server)
    print(f"{server.id} {module}: {'OK' if result.ok else 'FAILED'} — {result.message}")
    return 0 if result.ok else 1


def main(argv: list[str] | None = None) -> int:
    _setup_logging()
    p = argparse.ArgumentParser(prog="orchestrator-acme-cert-manager")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("list", help="list configured servers").set_defaults(func=cmd_list)

    for name, mod, fn in [("issue", "issue", "issue_or_renew"),
                          ("deploy", "deploy", "deploy"),
                          ("restart", "restart", "restart")]:
        sp = sub.add_parser(name, help=f"run the {name} step for one server")
        sp.add_argument("server_id")
        sp.set_defaults(func=lambda a, m=mod, f=fn: _single_step(a, m, f))

    rp = sub.add_parser("renew", help="run full pipeline for one server")
    rp.add_argument("server_id")
    rp.add_argument("--force", action="store_true")
    rp.set_defaults(func=_renew_one)

    ra = sub.add_parser("renew-all", help="run full pipeline for all servers")
    ra.add_argument("--force", action="store_true", default=os.environ.get("FORCE_RENEW") == "true")
    ra.set_defaults(func=cmd_renew_all)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
