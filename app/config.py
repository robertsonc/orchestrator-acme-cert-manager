"""Load, validate, and persist server configuration in JSON."""
from __future__ import annotations

import json
import os
from pathlib import Path

from .models import ServerConfig

DATA_DIR = Path(os.environ.get("DATA_DIR", "/data"))
SERVERS_FILE = Path(os.environ.get("SERVERS_FILE", str(DATA_DIR / "servers.json")))
CERTS_DIR = DATA_DIR / "certs"
LOGS_DIR = DATA_DIR / "logs"

CF_TOKEN_ENV = "CF_DNS_API_TOKEN"  # env var Lego reads for the Cloudflare DNS-01 challenge


class ConfigError(Exception):
    pass


def _one(s: dict) -> ServerConfig:
    try:
        acme = s.get("acme", {})
        dns = s.get("dns", {})
        ssh = s.get("ssh", {})
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
            ssh_user=ssh.get("user", ""),
            ssh_key_path=ssh.get("key_path", ""),
            ssh_known_hosts=ssh.get("known_hosts", str(DATA_DIR / "ssh" / "known_hosts")),
            ssh_port=int(ssh.get("port", 22)),
            restart_command=ssh.get("restart_command", "sudo systemctl restart --no-block gms.service"),
            nginx_reload_command=ssh.get("nginx_reload_command", "sudo systemctl reload nginx"),
            api_key_env=s.get("api_key_env", "ORCH_API_KEY"),
            api_key=s.get("api_key", ""),
            verify_ssl=bool(s.get("verify_ssl", False)),
        )
    except KeyError as exc:
        raise ConfigError(f"server entry missing required field: {exc}") from exc


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


def load_servers() -> list[ServerConfig]:
    if not SERVERS_FILE.exists():
        return []
    raw = json.loads(SERVERS_FILE.read_text())
    entries = raw.get("servers", []) if isinstance(raw, dict) else raw
    return [_one(s) for s in entries]


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
