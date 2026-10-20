"""
app/issue.py — Phase 2: certificate issuance / renewal via the Lego ACME client.

Pipeline stage 1 of 3:  issue  ->  deploy  ->  restart

Obtains (or renews) a single RSA certificate for one Orchestrator using the
DNS-01 challenge against Cloudflare, then flattens Lego's output into the three
canonical files the deploy stage expects:

    <cert_dir>/<domain>.cer   leaf certificate only
    <cert_dir>/<domain>.key   private key
    <cert_dir>/ca.cer         issuer chain (intermediate + root)

Design notes:
  * Single RSA cert -> one issuance leg, so none of the ECC/RSA DNS-01 race
    that complicates the ClearPass tool.
  * "Renew only when due": the scheduled path uses `lego renew --days 30`, a
    no-op unless the cert is within 30 days of expiry. We detect whether a
    renewal actually happened (via the cert file's mtime) and report it in
    detail["renewed"] so renew.py can skip deploy+restart when nothing changed.
  * The Cloudflare token is resolved per-server (config.cf_token_for): an inline
    token on the server wins, otherwise the CF_DNS_API_TOKEN env var is used.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

from cryptography import x509

from . import config
from .models import ServerConfig, StepResult

log = logging.getLogger(__name__)

STEP = "issue"
LEGO_BIN = os.environ.get("LEGO_BIN", "lego")
RENEW_WINDOW_DAYS = int(os.environ.get("RENEW_WINDOW_DAYS", "30"))
CF_TOKEN_ENV = config.CF_TOKEN_ENV  # env var name Lego reads for the Cloudflare DNS-01 challenge

_ACME_URLS = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt_test": "https://acme-staging-v02.api.letsencrypt.org/directory",
}


def issue_or_renew(server: ServerConfig, force: bool = False) -> StepResult:
    """Issue or renew the certificate for one server.

    detail on success includes: renewed (bool), expiry (ISO str), serial (hex),
    and the three flattened file paths (cert/key/chain).
    """
    cf_token = config.cf_token_for(server)
    if not cf_token:
        return StepResult(
            step=STEP,
            ok=False,
            message=(f"No Cloudflare DNS token for {server.id!r}: set it in the "
                     f"server's settings, or export {CF_TOKEN_ENV}."),
        )

    if not server.acme_email:
        return StepResult(
            step=STEP,
            ok=False,
            message=f"acme.email is not set for server {server.id!r}.",
        )

    if config.is_lab_ca(server.acme_ca) and not config.lab_ca_available():
        return StepResult(
            step=STEP, ok=False,
            message=("The bundled lab CA is selected but is not configured: run "
                     "./setup.sh --with-ca --lab-domain <zone> (needs LAB_CA_HOST and the root at "
                     f"{config.LAB_CA_ROOT})."),
        )

    acme_url = _acme_url(server)
    cert_dir = config.cert_dir_for(server)                 # lego state + flattened files live here
    lego_cert = cert_dir / "certificates" / f"{server.domain}.crt"

    first_issue = not lego_cert.exists()
    pre_mtime = lego_cert.stat().st_mtime if lego_cert.exists() else None

    # Lego 5.3.1: everything except --log.*/--config is a `run` flag, and there
    # is no separate `renew` subcommand — `run` obtains or renews as needed.
    cmd = [
        LEGO_BIN,
        "run",
        "--accept-tos",
        "--email", server.acme_email,
        "--dns", server.dns_provider,
        "--domains", server.domain,
        "--key-type", server.key_type,
        "--server", acme_url,
        "--path", str(cert_dir),
        "--no-random-sleep",
        "--ipv4only",
        "--dns.propagation.wait", "60s",
        "--ari-disable",
    ]
    if force or first_issue:
        action = "issue"
        cmd.append("--renew-force")  # obtain even if an existing cert isn't due
        cmd.append("--no-random-sleep")  # skip Lego's up-to-2min politeness delay
    else:
        action = "renew"
        cmd.append("--renew-days")
        cmd.append(str(RENEW_WINDOW_DAYS))  # renew only if within N days of expiry
        cmd.append("--no-random-sleep")  # deterministic timing for the scheduled path

    # Inject the resolved Cloudflare token so Lego's DNS-01 provider can see it,
    # regardless of whether it came from the server config or the environment.
    env = lego_environment(server, cf_token)

    log.info("lego %s for %s (%s)", action, server.domain, acme_url)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=180)
    except subprocess.TimeoutExpired:
        log.error("lego %s timed out after 180s for %s", action, server.domain)
        return StepResult(
            step=STEP,
            ok=False,
            message=f"lego {action} timed out after 180s (DNS challenge likely stuck)",
            detail={},
        )

    if proc.returncode != 0:
        err = (proc.stderr.strip() or proc.stdout.strip())
        log.error("lego failed (%s): %s", proc.returncode, err)
        last = err.splitlines()[-1] if err else "no output"
        return StepResult(
            step=STEP,
            ok=False,
            message=f"lego {action} failed (exit {proc.returncode}): {last}",
            detail={"stderr": proc.stderr.strip()[-2000:], "stdout": proc.stdout.strip()[-2000:]},
        )

    if not lego_cert.exists():
        return StepResult(
            step=STEP,
            ok=False,
            message="lego reported success but produced no certificate file.",
            detail={"stdout": proc.stdout.strip()[-2000:]},
        )

    renewed = first_issue or pre_mtime is None or lego_cert.stat().st_mtime != pre_mtime

    # Always flatten so the canonical files exist for the deploy stage.
    leaf, key, chain = _flatten(cert_dir, server.domain)
    expiry, serial = _read_cert(leaf)

    msg = (f"Certificate {action}d for {server.domain} (expires {expiry})."
           if renewed else
           f"Certificate for {server.domain} still valid; no renewal needed.")

    return StepResult(
        step=STEP,
        ok=True,
        message=msg,
        detail={
            "renewed": renewed,
            "expiry": expiry,
            "serial": serial,
            "cert": str(leaf),
            "key": str(key),
            "chain": str(chain),
        },
    )


def _acme_url(server: ServerConfig) -> str:
    ca = (server.acme_ca or "letsencrypt").strip()
    if config.is_lab_ca(ca):
        return config.lab_ca_acme_url()
    return ca if ca.startswith("http") else _ACME_URLS.get(ca, _ACME_URLS["letsencrypt"])


def lego_environment(server: ServerConfig, cf_token: str) -> dict[str, str]:
    """Environment for the Lego subprocess: DNS credentials plus, for the bundled
    lab CA, the root certificate Lego must trust when talking to the directory."""
    env = os.environ.copy()
    env[CF_TOKEN_ENV] = cf_token
    if config.is_lab_ca(server.acme_ca):
        env["LEGO_CA_CERTIFICATES"] = str(config.LAB_CA_ROOT)
    return env


def _flatten(cert_dir: Path, domain: str) -> tuple[Path, Path, Path]:
    """Split Lego's output into <domain>.cer (leaf), <domain>.key, ca.cer (chain)."""
    src_full = cert_dir / "certificates" / f"{domain}.crt"           # leaf + chain
    src_key = cert_dir / "certificates" / f"{domain}.key"
    src_issuer = cert_dir / "certificates" / f"{domain}.issuer.crt"  # chain only

    leaf_out = cert_dir / f"{domain}.cer"
    key_out = cert_dir / f"{domain}.key"
    chain_out = cert_dir / "ca.cer"

    blocks = _split_pem(src_full.read_text())
    if not blocks:
        raise ValueError(f"No PEM certificates found in {src_full}")

    leaf_out.write_text(blocks[0] + "\n")
    if src_issuer.exists():
        chain_out.write_text(src_issuer.read_text().strip() + "\n")
    else:
        chain_out.write_text("\n".join(blocks[1:]).strip() + "\n")

    shutil.copyfile(src_key, key_out)
    try:
        os.chmod(key_out, 0o600)
    except OSError:
        pass

    return leaf_out, key_out, chain_out


def _split_pem(text: str) -> list[str]:
    """Return each PEM certificate block (BEGIN..END inclusive) as a string."""
    begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
    blocks, idx = [], 0
    while True:
        start = text.find(begin, idx)
        if start == -1:
            break
        stop = text.find(end, start)
        if stop == -1:
            break
        stop += len(end)
        blocks.append(text[start:stop].strip())
        idx = stop
    return blocks


def _read_cert(leaf_path: Path) -> tuple[str, str]:
    """Return (expiry_iso, serial_hex) for the leaf certificate."""
    cert = x509.load_pem_x509_certificate(leaf_path.read_bytes())
    not_after = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
    return not_after.isoformat(), format(cert.serial_number, "x")
