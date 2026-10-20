"""Startup / on-demand checks that turn silent misconfiguration into clear errors.

Covers the two failure classes seen in the field:

  * the server list being read from a path that is not persistently mounted
    (UI edits silently lost on container recreate; two divergent configs), and
  * SSH settings that look fine in the file but fail at activation time.

run(strict=True) returns a Report; the entrypoint exits non-zero on fatal
findings unless STRICT_STARTUP=false.
"""
from __future__ import annotations

import logging
import os
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from . import config, sshcheck, store

log = logging.getLogger("preflight")


@dataclass
class Finding:
    level: str          # "fatal" | "warn" | "info"
    code: str
    message: str

    def as_dict(self) -> dict:
        return {"level": self.level, "code": self.code, "message": self.message}


@dataclass
class Report:
    servers_file: str
    history_file: str
    in_container: bool
    config_mounted: bool | None
    findings: list[Finding] = field(default_factory=list)
    ssh_problems: dict[str, list[str]] = field(default_factory=dict)

    @property
    def fatal(self) -> list[Finding]:
        return [f for f in self.findings if f.level == "fatal"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.level == "warn"]

    @property
    def ok(self) -> bool:
        return not self.fatal

    def as_dict(self) -> dict:
        return {
            "servers_file": self.servers_file,
            "history_file": self.history_file,
            "in_container": self.in_container,
            "config_mounted": self.config_mounted,
            "findings": [f.as_dict() for f in self.findings],
            "ssh_problems": self.ssh_problems,
        }


def in_container() -> bool:
    if os.environ.get("IN_CONTAINER", "").lower() in ("1", "true", "yes"):
        return True
    return Path("/.dockerenv").exists()


def is_persistently_mounted(path: Path) -> bool | None:
    """True if the nearest existing ancestor of `path` is on a mount point
    other than the container root. None if that cannot be determined.
    """
    try:
        mounts = Path("/proc/self/mountinfo").read_text().splitlines()
    except OSError:
        return None
    mount_points = set()
    for line in mounts:
        parts = line.split()
        if len(parts) > 4:
            mount_points.add(parts[4])
    p = path.resolve() if path.exists() else path.parent.resolve()
    while True:
        if str(p) in mount_points and str(p) != "/":
            return True
        if p.parent == p:
            return False
        p = p.parent


def _same_content(a: Path, b: Path) -> bool:
    try:
        return a.read_bytes() == b.read_bytes()
    except OSError:
        return False


def _migrate_history() -> Finding | None:
    """Copy a legacy /data/history.json forward once (copy, never move)."""
    legacy, new = store.LEGACY_HISTORY_FILE, store.HISTORY_FILE
    if legacy.exists() and not new.exists() and legacy != new:
        try:
            new.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(legacy, new)
            return Finding("info", "history-migrated",
                           f"copied renewal history from {legacy} to {new}")
        except OSError as exc:
            return Finding("warn", "history-migrate-failed",
                           f"could not copy {legacy} to {new}: {exc}")
    return None


def check_config_paths(strict: bool = True) -> list[Finding]:
    out: list[Finding] = []
    active, legacy = config.SERVERS_FILE, config.LEGACY_SERVERS_FILE
    container = in_container()
    out.append(Finding("info", "config-path", f"active server configuration: {active}"))

    if container:
        mounted = is_persistently_mounted(active)
        if mounted is False:
            out.append(Finding(
                "fatal" if strict else "warn", "config-not-mounted",
                f"{active} is not on a bind mount or volume: every change made in the web UI "
                f"would be lost when the container is recreated. Mount ./config:/config and set "
                f"SERVERS_FILE=/config/servers.json (set STRICT_STARTUP=false to override)."))

    if legacy != active and legacy.exists():
        if not active.exists():
            out.append(Finding(
                "fatal" if strict else "warn", "legacy-config-only",
                f"a server configuration exists at the legacy path {legacy} but nothing exists at "
                f"the active path {active}. Starting now would present an empty server list. "
                f"Migrate it first: copy {legacy} to {active} on the host (config/servers.json), "
                f"compare both files for differing secrets, then restart. "
                f"See README: 'Migrating from /data/servers.json'."))
        elif not _same_content(legacy, active):
            out.append(Finding(
                "warn", "legacy-config-conflict",
                f"both {legacy} and {active} exist and differ. Only {active} is used. Diff them, "
                f"merge anything newer from the legacy file by hand, then delete the legacy file "
                f"so operators cannot edit the wrong one."))
        else:
            out.append(Finding("info", "legacy-config-duplicate",
                               f"{legacy} is an identical copy of {active}; it can be deleted."))

    if active.exists():
        try:
            if not os.access(active, os.W_OK):
                out.append(Finding("warn", "config-readonly",
                                   f"{active} is not writable; saves from the web UI will fail."))
        except OSError:
            pass
    else:
        parent = active.parent
        if parent.exists() and not os.access(parent, os.W_OK):
            out.append(Finding("warn", "config-dir-readonly",
                               f"{parent} is not writable; the web UI cannot create {active.name}."))

    mig = _migrate_history()
    if mig:
        out.append(mig)
    return out


def check_servers() -> tuple[list[Finding], dict[str, list[str]]]:
    out: list[Finding] = []
    ssh_problems: dict[str, list[str]] = {}
    try:
        servers = config.load_servers()
    except config.ConfigError as exc:
        return [Finding("fatal", "config-invalid", str(exc))], ssh_problems
    if not servers:
        out.append(Finding("info", "no-servers", "no servers configured yet (add one in the web UI)"))
        return out, ssh_problems
    for s in servers:
        probs = sshcheck.validate(s)
        if probs:
            ssh_problems[s.id] = probs
            out.append(Finding("warn", "ssh-config",
                               f"{s.id}: SSH activation will fail until fixed: " + " | ".join(probs)))
        if config.is_lab_ca(s.acme_ca) and not config.lab_ca_available():
            out.append(Finding("warn", "lab-ca-missing",
                               f"{s.id}: the bundled lab CA is selected but LAB_CA_HOST is unset or "
                               f"{config.LAB_CA_ROOT} is missing; run ./setup.sh --with-ca."))
        if not s.verify_ssl:
            out.append(Finding("info", "tls-unverified",
                               f"{s.id}: verify_ssl is off; Orchestrator API calls do not verify the "
                               f"appliance certificate. Enable it once the production certificate is live."))
        if not (s.api_key or os.environ.get(s.api_key_env)):
            out.append(Finding("warn", "api-key-missing",
                               f"{s.id}: no Orchestrator API key (inline or {s.api_key_env})."))
        if not config.cf_token_for(s):
            out.append(Finding("warn", "cf-token-missing",
                               f"{s.id}: no Cloudflare DNS token (inline or {config.CF_TOKEN_ENV})."))
    return out, ssh_problems


def run(strict: bool | None = None) -> Report:
    if strict is None:
        strict = os.environ.get("STRICT_STARTUP", "true").lower() not in ("0", "false", "no")
    findings = check_config_paths(strict=strict)
    sfind, ssh_problems = check_servers()
    findings.extend(sfind)
    return Report(
        servers_file=str(config.SERVERS_FILE),
        history_file=str(store.HISTORY_FILE),
        in_container=in_container(),
        config_mounted=is_persistently_mounted(config.SERVERS_FILE) if in_container() else None,
        findings=findings,
        ssh_problems=ssh_problems,
    )


def log_report(report: Report) -> None:
    for f in report.findings:
        lvl = {"fatal": logging.ERROR, "warn": logging.WARNING}.get(f.level, logging.INFO)
        log.log(lvl, "[%s] %s", f.code, f.message)
