"""Shared data types."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass
class ServerConfig:
    """One Orchestrator target, loaded from servers.json.

    Secrets are optional inline: if api_key / dns_api_token are set they are
    used for this server; if blank the tool falls back to the environment
    (api_key_env and CF_DNS_API_TOKEN respectively).
    """
    id: str
    name: str
    orchestrator_host: str
    domain: str
    acme_ca: str = "letsencrypt"          # letsencrypt | letsencrypt_test | ...
    acme_email: str = ""
    key_type: str = "rsa2048"             # Orchestrator serves a single RSA cert
    dns_provider: str = "cloudflare"
    dns_api_token: str = ""               # inline Cloudflare DNS token (else env CF_DNS_API_TOKEN)
    ssh_user: str = ""
    ssh_key_path: str = ""
    ssh_known_hosts: str = ""
    ssh_port: int = 22
    restart_command: str = "sudo systemctl restart --no-block gms.service"
    nginx_reload_command: str = "sudo systemctl reload nginx"
    api_key_env: str = "ORCH_API_KEY"     # env var name used when api_key is blank
    api_key: str = ""                     # inline Orchestrator API key (else api_key_env)
    verify_ssl: bool = False
    ca_bundle: str = ""                   # optional CA bundle (PEM) used when verify_ssl is on
    ca_bundle_mode: str = "exclusive"     # exclusive: ca_bundle is the ONLY trust; additive: + system + lab roots

    @property
    def requests_verify(self):
        """Legacy view of the trust setting: a CA bundle path, True, or False.

        deploy.py uses config.api_trust_bundle(), which honours ca_bundle_mode and
        adds the lab root; this property keeps the exclusive semantics of ca_bundle.
        """
        if not self.verify_ssl:
            return False
        return self.ca_bundle or True

    @property
    def base_url(self) -> str:
        return f"https://{self.orchestrator_host}/gms/rest/gms/httpsCertificate"


@dataclass
class StepResult:
    """Outcome of a single pipeline step (issue / deploy / restart)."""
    step: str
    ok: bool
    message: str = ""
    detail: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {"step": self.step, "ok": self.ok, "message": self.message, "detail": self.detail}


@dataclass
class RenewalRecord:
    """A single renewal attempt, persisted for the web UI history."""
    server_id: str
    timestamp: str
    outcome: str                          # success | failed | skipped
    steps: list[dict[str, Any]] = field(default_factory=list)
    not_after: Optional[str] = None
    serial: Optional[str] = None
    kind: str = "renew"                   # scheduled | renew (forced) | redeploy
    elapsed_s: Optional[float] = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "server_id": self.server_id,
            "timestamp": self.timestamp,
            "outcome": self.outcome,
            "steps": self.steps,
            "not_after": self.not_after,
            "serial": self.serial,
            "kind": self.kind,
            "elapsed_s": self.elapsed_s,
        }
