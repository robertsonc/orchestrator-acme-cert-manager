"""Read-only system state for the web UI's System page and /api/status.

Everything here is observation: version, which environment variables are set
(secrets reported as present/absent, never their value), the scheduler, the SSH
material the activation step depends on, and the bundled lab CA. Each item that
cannot be changed from the UI carries a ``via`` string naming the host-side
command, setup.sh flag or .env key that configures it, so the UI can point the
operator at the right place instead of leaving the dependency implicit.
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import logging
import os
from pathlib import Path

from . import __version__, config, sshcheck, store

log = logging.getLogger("sysinfo")

CRONTAB = Path(os.environ.get("CRONTAB_FILE", "/app/crontab"))
_PROBE_TIMEOUT = 4

HOST_ENV = "edit .env on the Docker host, then: docker compose down && docker compose up -d"

# name, kind ("secret" | "value" | "flag"), default, what it does, where it is set
ENV_SPEC: list[tuple[str, str, str, str, str]] = [
    ("CF_DNS_API_TOKEN", "secret", "", "Cloudflare DNS-01 token used when a server has no inline token.", HOST_ENV),
    ("ORCH_API_KEY", "secret", "", "Orchestrator API key used when a server has no inline key.", HOST_ENV),
    ("NOTIFY_WEBHOOK_URL", "secret", "", "Incoming webhook for failure alerts (blank disables alerts).", HOST_ENV),
    ("NOTIFY_ON", "value", "failed", "Alert on 'failed' runs only, or 'all'.", HOST_ENV),
    ("RENEW_WINDOW_DAYS", "value", "30", "Scheduled renewals issue when this many days or fewer remain.", HOST_ENV),
    ("STRICT_STARTUP", "value", "true", "Refuse to start on an unmounted or legacy-only configuration.", HOST_ENV),
    ("DEPLOY_VALIDATION_ATTEMPTS", "value", "3", "Retries for transient 502/503/504 answers during validation.", HOST_ENV),
    ("DEPLOY_RETRY_BACKOFF", "value", "5", "Base seconds between validation retries, doubled each time.", HOST_ENV),
    ("DEPLOY_HTTP_TIMEOUT", "value", "30", "Per-request timeout for Orchestrator API calls.", HOST_ENV),
    ("TZ", "value", "UTC", "Container time zone: cron schedule and log timestamps.", HOST_ENV),
    ("LOG_LEVEL", "value", "INFO", "Logging verbosity.", HOST_ENV),
    ("LAB_CA_HOST", "value", "", "Bundled lab CA hostname (pinned at init).", "./setup.sh --with-ca --lab-domain <zone> [--ca-host <name>]"),
    ("LAB_CA_PORT", "value", "9000", "Port step-ca listens on inside and outside the container (pinned at init).", "./setup.sh --with-ca --ca-port <port> (only at first init)"),
    ("LAB_CA_DOMAIN", "value", "", "Name constraint: the lab CA issues only under this domain (pinned at init).", "./setup.sh --with-ca --lab-domain <zone>"),
]


# ----------------------------------------------------------------------------- environment
def environment() -> list[dict]:
    """Presence of every documented environment variable. Secret values are never returned."""
    out = []
    for name, kind, default, what, via in ENV_SPEC:
        raw = os.environ.get(name)
        if raw is None or raw == "":
            state = "default" if default else "unset"
            value = default if default else ""
        else:
            state = "set"
            value = "" if kind == "secret" else raw
        out.append({"name": name, "kind": kind, "state": state, "value": value,
                    "default": default, "description": what, "via": via})
    return out


# ----------------------------------------------------------------------------- scheduler
def _parse_cron_line(line: str) -> dict | None:
    parts = line.split(None, 5)
    if len(parts) < 6:
        return None
    minute, hour, dom, month, dow, command = parts
    entry = {"expr": " ".join(parts[:5]), "command": command.strip(), "next_run": None}
    if dom == "*" and month == "*" and dow == "*" and minute.isdigit() and hour.isdigit():
        now = datetime.datetime.now().astimezone()
        cand = now.replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)
        if cand <= now:
            cand += datetime.timedelta(days=1)
        entry["next_run"] = cand.isoformat(timespec="minutes")
    return entry


def scheduler() -> dict:
    """What supercronic runs and when; plus the last scheduled run from history."""
    entries = []
    try:
        for line in CRONTAB.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            e = _parse_cron_line(line)
            if e:
                entries.append(e)
    except OSError:
        pass
    last = next((r for r in store.all_records() if (r.get("kind") or "renew") == "scheduled"), None)
    nxt = min((e["next_run"] for e in entries if e["next_run"]), default=None)
    return {
        "crontab": str(CRONTAB), "entries": entries, "next_run": nxt,
        "window_days": os.environ.get("RENEW_WINDOW_DAYS", "30"),
        "tz": os.environ.get("TZ", "UTC"),
        "last_scheduled": {"timestamp": last.get("timestamp"), "outcome": last.get("outcome"),
                           "server_id": last.get("server_id")} if last else None,
        "via": "config/crontab in the image (rebuild to change); RENEW_WINDOW_DAYS in .env",
    }


# ----------------------------------------------------------------------------- SSH material
def _key_info(path: str) -> dict:
    info = {"path": path, "exists": bool(path) and Path(path).is_file(), "type": None, "bits": None,
            "fingerprint": None, "problem": None, "readable": None}
    if not info["exists"]:
        return info
    info["readable"] = os.access(path, os.R_OK)
    try:
        key = sshcheck.load_private_key(path)
    except sshcheck.SSHConfigError as exc:
        info["problem"] = str(exc)
        return info
    info["type"] = key.get_name()
    info["bits"] = key.get_bits()
    digest = hashlib.sha256(key.asbytes()).digest()
    info["fingerprint"] = "SHA256:" + base64.b64encode(digest).decode().rstrip("=")
    return info


def _known_hosts_info(path: str) -> dict:
    info = {"path": path, "exists": bool(path) and Path(path).is_file(), "hosts": [], "problem": None}
    if not info["exists"]:
        return info
    try:
        import paramiko
        hk = paramiko.HostKeys(path)
        info["hosts"] = sorted(hk.keys())
    except Exception as exc:  # noqa: BLE001
        info["problem"] = str(exc)
    return info


def ssh_material() -> dict:
    """The default key and known_hosts, plus any other paths servers reference."""
    servers = []
    try:
        loaded = config.load_servers()
    except config.ConfigError:
        loaded = []
    keys: dict[str, dict] = {}
    khs: dict[str, dict] = {}
    for s in loaded:
        kp = s.ssh_key_path or config.DEFAULT_SSH_KEY
        kh = s.ssh_known_hosts or config.DEFAULT_KNOWN_HOSTS
        keys.setdefault(kp, _key_info(kp))
        khs.setdefault(kh, _known_hosts_info(kh))
        name = sshcheck.known_hosts_entry_name(s.orchestrator_host, s.ssh_port)
        servers.append({"id": s.id, "host": s.orchestrator_host, "port": s.ssh_port, "user": s.ssh_user,
                        "key_path": kp, "known_hosts": kh, "entry": name,
                        "pinned": name in khs[kh]["hosts"], "problems": sshcheck.validate(s)})
    keys.setdefault(config.DEFAULT_SSH_KEY, _key_info(config.DEFAULT_SSH_KEY))
    khs.setdefault(config.DEFAULT_KNOWN_HOSTS, _known_hosts_info(config.DEFAULT_KNOWN_HOSTS))
    return {
        "key_files": list(keys.values()), "known_hosts_files": list(khs.values()), "servers": servers,
        "mount": f"{config.SSH_DIR} (./data/ssh on the host, mounted read-only)",
        "via_key": "./setup.sh generates data/ssh/orch_restart (RSA-4096, no passphrase; --key-type ed25519)",
        "via_known_hosts": "./setup.sh --host <orchestrator> pins the host key after you confirm the fingerprint (--trust-host-key skips the prompt)",
        "via_sudoers": "./setup.sh --host <orchestrator> --install-sudoers writes the scoped NOPASSWD rule (after confirmation)",
    }


# ----------------------------------------------------------------------------- lab CA
def _probe_ca(base: str) -> dict:
    """GET /health on the CA with the lab root as the only trust anchor. Read-only."""
    import requests  # lazy: keeps module import light for the CLI
    try:
        r = requests.get(f"{base}/health", timeout=_PROBE_TIMEOUT, verify=str(config.LAB_CA_ROOT))
        ok = r.status_code == 200 and "ok" in r.text.lower()
        return {"ok": ok, "status": r.status_code, "error": None if ok else r.text[:120]}
    except requests.RequestException as exc:
        return {"ok": False, "status": None, "error": str(exc)[:200]}


def lab_ca(probe: bool = False) -> dict:
    configured = bool(config.LAB_CA_HOST)
    base = config.lab_ca_base_url()
    root_present = config.LAB_CA_ROOT.is_file()
    retired = sorted(p.name for p in config.LAB_CA_RETIRED_DIR.glob("*.crt")) if config.LAB_CA_RETIRED_DIR.is_dir() else []
    d = {
        "configured": configured, "available": config.lab_ca_available(),
        "host": config.LAB_CA_HOST, "port": config.LAB_CA_PORT, "domain": os.environ.get("LAB_CA_DOMAIN", ""),
        "url": base, "acme_url": config.lab_ca_acme_url(),
        "roots_url": f"{base}/roots.pem" if base else "", "crl_url": f"{base}/1.0/crl" if base else "",
        "root_file": str(config.LAB_CA_ROOT), "root_present": root_present,
        "intermediate_present": config.LAB_CA_INTERMEDIATE.is_file(),
        "fingerprint": config.lab_ca_root_fingerprint() if root_present else "",
        "issuers": sorted(config.lab_ca_issuer_names()) if root_present else [],
        "root_key_offline": config.LAB_CA_OFFLINE_MARKER.is_file(),
        "retired_roots": retired,
        "provisioner": config.LAB_CA_PROVISIONER,
        "health": None,
        "via": "./setup.sh --with-ca --lab-domain <zone> on the Docker host (identity is pinned at init)",
        "ops": [
            {"name": "Initialise or resume", "cmd": "./setup.sh --with-ca --lab-domain <zone>",
             "note": "Idempotent; refuses a different identity."},
            {"name": "Revoke a certificate",
             "cmd": f"docker compose exec lab-ca step ca revoke <serial> --ca-url {base or 'https://<host>:<port>'} "
                    f"--root /home/step/certs/root_ca.crt --provisioner lab-admin",
             "note": "Regenerates the CRL. Provisioner password: data/pki/secrets/password."},
            {"name": "Root rollover", "cmd": "./setup.sh --rotate-root",
             "note": "New root, same identity; old root stays trusted for API calls until every lab-CA server is re-issued."},
            {"name": "Move the root key offline", "cmd": "mv data/pki-root <offline storage>",
             "note": "Required before any client trusts the root."},
        ],
    }
    if probe and configured and root_present:
        d["health"] = _probe_ca(base)
    return d


# ----------------------------------------------------------------------------- host-only operations
HOST_OPERATIONS = [
    {"name": "Upgrade readiness", "cmd": "./upgrade-check.sh [--with-ca]",
     "note": "Read-only host report: Docker, Compose, .env keys and secrets, layout, SSH material, lab CA prerequisites. The container cannot see the host."},
    {"name": "Docker Engine + Compose plugin", "cmd": "./setup.sh", "note": "Installs from Docker's repository if missing; enables the daemon; adds you to the docker group."},
    {"name": "SSH key pair", "cmd": "./setup.sh [--key-type ed25519]", "note": "data/ssh/orch_restart; mounted read-only into the container."},
    {"name": "Orchestrator host key", "cmd": "./setup.sh --host <orchestrator> [--trust-host-key]", "note": "ssh-keyscan, fingerprint confirmation, pinned in data/ssh/known_hosts."},
    {"name": "Public key on the appliance", "cmd": "./setup.sh --host <orchestrator>", "note": "ssh-copy-id (prompts for the account password once) or printed manual steps."},
    {"name": "Scoped sudoers rule", "cmd": "./setup.sh --host <orchestrator> --install-sudoers", "note": "Writes one drop-in under /etc/sudoers.d after confirmation and visudo validation."},
    {"name": "Environment variables", "cmd": "edit .env; docker compose down && docker compose up -d", "note": "Secrets, alerting, retry tuning, time zone. A restart is required."},
    {"name": "Reset the admin account", "cmd": "rm config/admin.json", "note": "The next visit shows the Setup page."},
    {"name": "Rebuild after a code update", "cmd": "git pull && docker compose up -d --build", "note": "See UPGRADING.md for the version-specific steps."},
]


def snapshot(report, probe_ca: bool = False) -> dict:
    """Everything the System page shows, JSON-serialisable."""
    d = report.as_dict()
    d["version"] = __version__
    d["problems"] = [f.as_dict() for f in report.findings if f.level in ("fatal", "warn")]
    d["paths"] = {
        "config_dir": str(config.CONFIG_DIR), "data_dir": str(config.DATA_DIR),
        "certs_dir": str(config.CERTS_DIR), "trust_dir": str(config.TRUST_DIR),
        "admin_present": (config.SERVERS_FILE.parent / "admin.json").is_file(),
    }
    d["environment"] = environment()
    d["scheduler"] = scheduler()
    d["ssh"] = ssh_material()
    d["lab_ca"] = lab_ca(probe=probe_ca)
    d["host_operations"] = HOST_OPERATIONS
    return d
