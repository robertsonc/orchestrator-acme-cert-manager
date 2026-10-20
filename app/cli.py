"""Command-line entry point: list / check / ssh-test / issue / deploy / restart / renew / renew-all."""
from __future__ import annotations

import argparse
import json
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
    from . import store
    try:
        servers = config.load_servers()
    except config.ConfigError as exc:
        print(f"configuration error: {exc}", file=sys.stderr)
        return 2
    print(f"Configuration: {config.SERVERS_FILE}")
    if not servers:
        print("No servers configured. Add one in the web UI (Settings) or edit servers.json.")
        return 0
    for s in servers:
        latest = store.latest_for(s.id)
        status = latest["outcome"] if latest else "never run"
        print(f"  {s.id:<16} {s.domain:<36} CA={s.acme_ca:<16} last={status}")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    """Preflight: configuration path/persistence, SSH settings, credentials."""
    from . import preflight
    report = preflight.run(strict=None if not args.lenient else False)
    if args.json:
        print(json.dumps(report.as_dict(), indent=2))
    else:
        print(f"Configuration: {report.servers_file}")
        print(f"History:       {report.history_file}")
        if report.in_container:
            print(f"Persistent:    {'yes' if report.config_mounted else 'NO' if report.config_mounted is False else 'unknown'}")
        for f in report.findings:
            tag = {"fatal": "FATAL", "warn": "WARN ", "info": "info "}[f.level]
            print(f"  [{tag}] {f.code}: {f.message}")
        print("Result: " + ("OK" if report.ok else "FAILED — fix the FATAL items above"))
    return 0 if report.ok else 1


def cmd_ssh_test(args: argparse.Namespace) -> int:
    from . import sshcheck
    try:
        server = config.get_server(args.server_id)
    except config.ConfigError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    res = sshcheck.test_connection(server)
    print(f"{server.id} ssh-test: {'OK' if res.ok else 'FAILED'} — {res.message}")
    for c in res.detail.get("checks", []):
        state = "ok " if c.get("ok") else "FAIL"
        print(f"  [{state}] {c.get('command')}" + (f"  -> {c.get('hint') or c.get('error')}" if not c.get("ok") else ""))
    return 0 if res.ok else 1


def cmd_ca_info(_: argparse.Namespace) -> int:
    """Bundled lab CA: endpoints, root fingerprint, trust-store hints."""
    if not config.LAB_CA_HOST:
        print("Lab CA not configured (LAB_CA_HOST unset). Run ./setup.sh --with-ca --lab-domain <zone>.")
        return 1
    base = config.lab_ca_base_url()
    print(f"Lab CA:          {base}")
    print(f"ACME directory:  {config.lab_ca_acme_url()}")
    print(f"Root download:   {base}/roots.pem")
    print(f"CRL:             {base}/1.0/crl")
    if config.LAB_CA_ROOT.is_file():
        print(f"Root file:       {config.LAB_CA_ROOT}")
        print(f"Root SHA-256:    {config.lab_ca_root_fingerprint()}")
        names = sorted(config.lab_ca_issuer_names())
        print("Issuers:         " + "; ".join(names))
        print("Root key:        " + ("offline (marker present)" if config.LAB_CA_OFFLINE_MARKER.is_file()
                                     else "UNKNOWN — marker missing; verify the key is not in the online volume"))
        print(f"API trust:       {config.api_trust_bundle()} (servers without ca_bundle)")
    else:
        print(f"Root file:       {config.LAB_CA_ROOT} (MISSING — mount ./data/pki/certs and run setup.sh --with-ca)")
        return 1
    print("Trust the root on clients after confirming the fingerprint out of band (see README 'Bundled lab CA').")
    return 0


def _renew_one(args: argparse.Namespace) -> int:
    from . import renew
    server = config.get_server(args.server_id)
    rec = renew.renew_server(server, force=args.force)
    print(f"{server.id}: {rec.outcome}")
    return 0 if rec.outcome == "success" else 1


def _redeploy_one(args: argparse.Namespace) -> int:
    from . import renew
    server = config.get_server(args.server_id)
    rec = renew.redeploy_server(server)
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

    ck = sub.add_parser("check", help="preflight: config persistence, SSH settings, credentials")
    ck.add_argument("--json", action="store_true", help="machine-readable output")
    ck.add_argument("--lenient", action="store_true", help="report fatal findings as warnings")
    ck.set_defaults(func=cmd_check)

    sub.add_parser("ca-info", help="bundled lab CA endpoints and root fingerprint").set_defaults(func=cmd_ca_info)

    st = sub.add_parser("ssh-test", help="verify SSH key auth and sudo authorization (no restart)")
    st.add_argument("server_id")
    st.set_defaults(func=cmd_ssh_test)

    for name, mod, fn in [("issue", "issue", "issue_or_renew"),
                          ("deploy", "deploy", "deploy"),
                          ("restart", "restart", "restart")]:
        sp = sub.add_parser(name, help=f"run the {name} step for one server")
        sp.add_argument("server_id")
        sp.set_defaults(func=lambda a, m=mod, f=fn: _single_step(a, m, f))

    rp = sub.add_parser("renew", help="run full pipeline for one server (contacts the ACME CA)")
    rp.add_argument("server_id")
    rp.add_argument("--force", action="store_true")
    rp.set_defaults(func=_renew_one)

    rd = sub.add_parser("redeploy", help="deploy + activate the certificate already on disk (no CA contact)")
    rd.add_argument("server_id")
    rd.set_defaults(func=_redeploy_one)

    ra = sub.add_parser("renew-all", help="run full pipeline for all servers")
    ra.add_argument("--force", action="store_true", default=os.environ.get("FORCE_RENEW") == "true")
    ra.set_defaults(func=cmd_renew_all)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
