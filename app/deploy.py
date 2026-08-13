"""Deploy the cert to Orchestrator via the httpsCertificate REST API.
(Phase 3 — port of the validated deploy_orchestrator.sh.)

deploy(server) uploads the current flattened cert from cert_dir_for(server).
deploy_paths(...) uploads a specific cert/key/chain — used by the rollback path
to re-install the last-known-good certificate.
"""
from __future__ import annotations

import base64
import logging
from pathlib import Path

import requests
import urllib3

from . import config
from .models import ServerConfig, StepResult

log = logging.getLogger("deploy")

STEP = "deploy"
_CERT_MEDIA = "application/x-x509-ca-cert"
_KEY_MEDIA = "application/octet-stream"
_TIMEOUT = 30


def deploy(server: ServerConfig) -> StepResult:
    """Upload the current flattened certificate for this server."""
    cert_dir = config.cert_dir_for(server)
    return deploy_paths(
        server,
        cert_dir / f"{server.domain}.cer",
        cert_dir / f"{server.domain}.key",
        cert_dir / "ca.cer",
    )


def deploy_paths(server: ServerConfig, cert_file: Path, key_file: Path, ca_file: Path) -> StepResult:
    """Upload a specific cert/key/chain trio (validate, then install)."""
    for f in (cert_file, key_file, ca_file):
        if not Path(f).exists():
            return StepResult(STEP, ok=False,
                              message=f"missing file for deploy: {Path(f).name}")

    try:
        api_key = config.api_key_for(server)
    except config.ConfigError as exc:
        return StepResult(STEP, ok=False, message=str(exc))

    payload = {
        "certificateData": _data_uri(Path(cert_file).read_bytes(), _CERT_MEDIA),
        "keyData": _data_uri(Path(key_file).read_bytes(), _KEY_MEDIA),
        "intermediateCertFileContent": _data_uri(Path(ca_file).read_bytes(), _CERT_MEDIA),
    }
    headers = {"Content-Type": "application/json", "X-Auth-Token": api_key}
    base_url = server.base_url

    if not server.verify_ssl:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    r_val = _post(f"{base_url}/validation", payload, headers, server.verify_ssl)
    if r_val is None:
        return StepResult(STEP, ok=False, message="validation request failed to connect")
    if not r_val.ok:
        return StepResult(STEP, ok=False,
                          message=f"validation rejected (HTTP {r_val.status_code})",
                          detail={"phase": "validation", "status": r_val.status_code,
                                  "body": r_val.text[:2000]})

    r_ins = _post(base_url, payload, headers, server.verify_ssl)
    if r_ins is None:
        return StepResult(STEP, ok=False, message="install request failed to connect")
    if not r_ins.ok:
        return StepResult(STEP, ok=False,
                          message=f"install rejected (HTTP {r_ins.status_code})",
                          detail={"phase": "install", "status": r_ins.status_code,
                                  "body": r_ins.text[:2000]})

    log.info("deploy(%s): uploaded (validation %s, install %s)",
             server.id, r_val.status_code, r_ins.status_code)
    return StepResult(STEP, ok=True,
                      message=(f"Certificate uploaded to {server.orchestrator_host} "
                               f"(validation {r_val.status_code}, install {r_ins.status_code})."),
                      detail={"validation_status": r_val.status_code,
                              "install_status": r_ins.status_code})


def _data_uri(raw: bytes, media_type: str) -> str:
    return f"data:{media_type};base64,{base64.b64encode(raw).decode('ascii')}"


def _post(url: str, payload: dict, headers: dict, verify_ssl: bool):
    try:
        return requests.post(url, json=payload, headers=headers,
                             verify=verify_ssl, timeout=_TIMEOUT)
    except requests.RequestException as exc:
        log.error("deploy POST %s failed: %s", url, exc)
        return None