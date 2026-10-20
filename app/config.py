"""Load, validate, and persist server configuration in JSON.

Path resolution (all overridable through the environment):

    CONFIG_DIR     persistent, writable directory (default /config). Holds
                   servers.json, admin.json, session.secret and history.json.
    DATA_DIR       runtime data root (default /data). Holds certs/, logs/, ssh/.
    SERVERS_FILE   explicit path to the server list (default CONFIG_DIR/servers.json).

Earlier releases defaulted SERVERS_FILE to DATA_DIR/servers.json, which is
*not* covered by the documented bind mounts, so UI edits were lost when the
container was recreated. LEGACY_SERVERS_FILE is kept only so preflight can
detect that situation and tell the operator how to migrate.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from .models import ServerConfig

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
CONFIG_DIR = Path(os.environ.get("CONFIG_DIR", "/config"))
SERVERS_FILE = Path(os.environ.get("SERVERS_FILE") or (CONFIG_DIR / "servers.json"))
LEGACY_SERVERS_FILE = DATA_DIR / "servers.json"
CERTS_DIR = DATA_DIR / "certs"
LOGS_DIR = DATA_DIR / "logs"
SSH_DIR = DATA_DIR / "ssh"

DEFAULT_SSH_KEY = str(SSH_DIR / "orch_restart")
DEFAULT_KNOWN_HOSTS = str(SSH_DIR / "known_hosts")
DEFAULT_RESTART_COMMAND = "sudo /bin/systemctl restart --no-block gms.service"
DEFAULT_NGINX_RELOAD_COMMAND = "sudo /bin/systemctl reload nginx"

CF_TOKEN_ENV = "CF_DNS_API_TOKEN"  # env var Lego reads for the Cloudflare DNS-01 challenge

# Bundled lab CA (step-ca), optional. See README "Bundled lab CA".
LAB_CA_ID = "lab"                                  # acme.ca value that selects it
LAB_CA_HOST = os.environ.get("LAB_CA_HOST", "")
LAB_CA_PORT = int(os.environ.get("LAB_CA_PORT", "9000") or 9000)   # step-ca listens on this port inside and outside
LAB_CA_PROVISIONER = os.environ.get("LAB_CA_PROVISIONER", "lab")
LAB_CA_CERTS_DIR = Path(os.environ.get("LAB_CA_CERTS_DIR", str(DATA_DIR / "pki" / "certs")))
LAB_CA_ROOT = LAB_CA_CERTS_DIR / "root_ca.crt"
LAB_CA_INTERMEDIATE = LAB_CA_CERTS_DIR / "intermediate_ca.crt"
LAB_CA_OFFLINE_MARKER = LAB_CA_CERTS_DIR / "root-key-offline"   # written by lab-ca-init.sh


class ConfigError(Exception):
    pass


def _one(s: dict) -> ServerConfig:
    try:
        acme = s.get("acme", {}) or {}
        dns = s.get("dns", {}) or {}
        ssh = s.get("ssh", {}) or {}
        return ServerConfig(
            id=s["id"],
            name=s.get("name", s["id"]),
            orchestrator_host=s["orchestrator_host"],
            domain=s.get("domain") or s["orchestrator_host"],
            acme_ca=acme.get("ca", "letsencrypt"),
            acme_email=acme.get("email", ""),
            key_type=acme.get("key_type", "rsa2048"),
            dns_provider=dns.get("provider", "cloudflare"),
            dns_api_token=dns.get("api_token", ""),
            ssh_user=(ssh.get("user") or "").strip(),
            ssh_key_path=(ssh.get("key_path") or "").strip(),
            ssh_known_hosts=(ssh.get("known_hosts") or DEFAULT_KNOWN_HOSTS).strip(),
            ssh_port=int(ssh.get("port") or 22),
            restart_command=ssh.get("restart_command", DEFAULT_RESTART_COMMAND),
            nginx_reload_command=ssh.get("nginx_reload_command", DEFAULT_NGINX_RELOAD_COMMAND),
            api_key_env=s.get("api_key_env", "ORCH_API_KEY"),
            api_key=s.get("api_key", ""),
            verify_ssl=bool(s.get("verify_ssl", False)),
            ca_bundle=(s.get("ca_bundle") or "").strip(),
        )
    except KeyError as exc:
        raise ConfigError(f"server entry missing required field: {exc}") from exc
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"server entry {s.get('id', '?')!r} has an invalid value: {exc}") from exc


def _to_dict(s: ServerConfig) -> dict:
    """Inverse of _one(): a ServerConfig back into the nested JSON shape."""
    return {
        "id": s.id,
        "name": s.name,
        "orchestrator_host": s.orchestrator_host,
        "domain": s.domain,
        "api_key_env": s.api_key_env,
        "api_key": s.api_key,
        "verify_ssl": s.verify_ssl,
        "ca_bundle": s.ca_bundle,
        "acme": {"ca": s.acme_ca, "email": s.acme_email, "key_type": s.key_type},
        "dns": {"provider": s.dns_provider, "api_token": s.dns_api_token},
        "ssh": {
            "user": s.ssh_user,
            "key_path": s.ssh_key_path,
            "known_hosts": s.ssh_known_hosts,
            "port": s.ssh_port,
            "restart_command": s.restart_command,
            "nginx_reload_command": s.nginx_reload_command,
        },
    }


def server_from_dict(s: dict) -> ServerConfig:
    """Public wrapper around _one() for building a ServerConfig from form data."""
    return _one(s)


def _parse_servers_file(path: Path) -> list[dict]:
    try:
        raw = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        raise ConfigError(f"{path} is not valid JSON: {exc}") from exc
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc
    entries = raw.get("servers", []) if isinstance(raw, dict) else raw
    if not isinstance(entries, list):
        raise ConfigError(f"{path}: expected a 'servers' list")
    return entries


def load_servers(path: Path | None = None) -> list[ServerConfig]:
    path = path or SERVERS_FILE
    if not path.exists():
        return []
    return [_one(s) for s in _parse_servers_file(path)]


def get_server(server_id: str) -> ServerConfig:
    for s in load_servers():
        if s.id == server_id:
            return s
    raise ConfigError(f"no server with id {server_id!r}")


def server_exists(server_id: str) -> bool:
    return any(s.id == server_id for s in load_servers())


def _lock_down(path: Path) -> None:
    """Restrict a secret-bearing file to owner read/write (best effort)."""
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def save_servers(servers: list[ServerConfig]) -> None:
    """Write the full server list back to servers.json.

    Writes in place rather than renaming a temp file over the target, because
    servers.json may be an individual Docker bind mount — os.replace() onto a
    mount point fails with EBUSY. A .bak copy is kept so a mid-write failure is
    still recoverable. Both files are chmod 600 because they now hold secrets.
    """
    SERVERS_FILE.parent.mkdir(parents=True, exist_ok=True)
    payload = {"servers": [_to_dict(s) for s in servers]}
    text = json.dumps(payload, indent=2) + "\n"
    if SERVERS_FILE.exists():
        bak = SERVERS_FILE.with_suffix(".json.bak")
        bak.write_text(SERVERS_FILE.read_text())
        _lock_down(bak)
    SERVERS_FILE.write_text(text)
    _lock_down(SERVERS_FILE)


def upsert_server(server: ServerConfig) -> None:
    """Insert a new server or replace an existing one in place (preserving order)."""
    servers = load_servers()
    for i, s in enumerate(servers):
        if s.id == server.id:
            servers[i] = server
            break
    else:
        servers.append(server)
    save_servers(servers)


def delete_server(server_id: str) -> bool:
    """Remove a server by id. Returns True if something was removed."""
    servers = load_servers()
    remaining = [s for s in servers if s.id != server_id]
    if len(remaining) == len(servers):
        return False
    save_servers(remaining)
    return True


def api_key_for(server: ServerConfig) -> str:
    """Resolve the Orchestrator API key: inline value first, then the env var."""
    key = server.api_key or os.environ.get(server.api_key_env, "")
    if not key:
        raise ConfigError(
            f"no Orchestrator API key for {server.id!r}: set it in the server's "
            f"settings, or export {server.api_key_env}"
        )
    return key


def cf_token_for(server: ServerConfig) -> str:
    """Resolve the Cloudflare DNS token: inline value first, then the env var."""
    return server.dns_api_token or os.environ.get(CF_TOKEN_ENV, "")


def cert_dir_for(server: ServerConfig) -> Path:
    d = CERTS_DIR / server.domain
    d.mkdir(parents=True, exist_ok=True)
    return d


def leaf_path_for(server: ServerConfig) -> Path:
    """The flattened leaf certificate for this server (may not exist yet)."""
    return CERTS_DIR / server.domain / f"{server.domain}.cer"


def is_staging_ca(acme_ca: str) -> bool:
    ca = (acme_ca or "").strip().lower()
    return ca == "letsencrypt_test" or "staging" in ca


def is_lab_ca(acme_ca: str) -> bool:
    return (acme_ca or "").strip().lower() == LAB_CA_ID


def ca_environment(acme_ca: str) -> str:
    """'lab' | 'staging' | 'production' for a configured acme.ca value."""
    if is_lab_ca(acme_ca):
        return "lab"
    return "staging" if is_staging_ca(acme_ca) else "production"


def lab_ca_base_url() -> str:
    return f"https://{LAB_CA_HOST}:{LAB_CA_PORT}" if LAB_CA_HOST else ""


def lab_ca_acme_url() -> str:
    """ACME directory of the bundled CA, or '' when it is not configured."""
    base = lab_ca_base_url()
    return f"{base}/acme/{LAB_CA_PROVISIONER}/directory" if base else ""


def lab_ca_available() -> bool:
    return bool(LAB_CA_HOST) and LAB_CA_ROOT.is_file()


_LAB_ISSUERS: tuple[float, frozenset[str]] = (-1.0, frozenset())


def lab_ca_issuer_names() -> frozenset[str]:
    """RFC 4514 subject names of the lab root and intermediate (cached by mtime).

    A certificate whose issuer is one of these was issued by the lab CA.
    """
    global _LAB_ISSUERS
    files = [f for f in (LAB_CA_ROOT, LAB_CA_INTERMEDIATE) if f.is_file()]
    if not files:
        return frozenset()
    stamp = max(f.stat().st_mtime for f in files)
    if stamp == _LAB_ISSUERS[0]:
        return _LAB_ISSUERS[1]
    from cryptography import x509  # lazy import
    names = set()
    for f in files:
        try:
            names.add(x509.load_pem_x509_certificate(f.read_bytes()).subject.rfc4514_string())
        except (ValueError, OSError):
            continue
    _LAB_ISSUERS = (stamp, frozenset(names))
    return _LAB_ISSUERS[1]


TRUST_DIR = CONFIG_DIR / "trust"
COMBINED_TRUST_FILE = TRUST_DIR / "api-trust.pem"


def api_trust_bundle(ca_bundle: str = "") -> str | bool:
    """Trust material for verified Orchestrator API calls.

    Returns a PEM path that holds the system/certifi roots PLUS the lab CA root
    (when the lab CA is configured) PLUS the server's own ca_bundle, so that a
    verified call succeeds whatever the appliance currently serves: a public
    certificate before a migration to the lab CA, a lab certificate during a
    rollback to a public one, or a private-CA certificate the operator trusts.
    Returns True (plain system trust) when nothing needs adding.
    """
    extras = [f for f in (LAB_CA_ROOT if LAB_CA_HOST else None,
                          Path(ca_bundle) if ca_bundle else None) if f and f.is_file()]
    if not extras:
        return True
    try:
        import certifi
        system = Path(certifi.where())
    except ImportError:  # pragma: no cover
        system = None
    parts = [system] + extras if system and system.is_file() else extras
    key = "|".join(f"{f}:{f.stat().st_mtime_ns}" for f in parts)
    TRUST_DIR.mkdir(parents=True, exist_ok=True)
    stamp = TRUST_DIR / "api-trust.stamp"
    if COMBINED_TRUST_FILE.is_file() and stamp.is_file() and stamp.read_text() == key:
        return str(COMBINED_TRUST_FILE)
    COMBINED_TRUST_FILE.write_bytes(b"".join(f.read_bytes().rstrip(b"\n") + b"\n" for f in parts))
    stamp.write_text(key)
    return str(COMBINED_TRUST_FILE)


def lab_ca_root_fingerprint() -> str:
    """SHA-256 of the root certificate in DER form (same value `step certificate fingerprint` prints)."""
    if not LAB_CA_ROOT.is_file():
        return ""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_pem_x509_certificate(LAB_CA_ROOT.read_bytes())
    return cert.fingerprint(hashes.SHA256()).hex()
