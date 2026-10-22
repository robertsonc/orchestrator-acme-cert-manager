"""
app/issue.py — stage 1 of 3: certificate issuance / renewal via the Lego ACME client.

Pipeline:  issue  ->  deploy  ->  activate   (one issue per certificate, then
                                              deploy + activate per target)

Obtains (or renews) a single RSA certificate for one name using the DNS-01
challenge, then flattens Lego's output into the three canonical files the
drivers expect:

    <cert_dir>/<domain>.cer   leaf certificate only
    <cert_dir>/<domain>.key   private key
    <cert_dir>/ca.cer         issuer chain (intermediate + root)

Design notes:
  * "Renew only when due": the scheduled path decides *here*, from the
    certificate's own validity (renew once a third of the lifetime remains;
    RENEW_WINDOW_DAYS is an absolute override), and does not run Lego at all
    when nothing is due — no CA contact, no ACME account touch.
  * ARI (renewal information) is left on so a same-CA renewal carries the
    "replaces" link. It is disabled only when the certificate on disk came
    from a different environment (staging <-> production <-> lab), where the
    CA would reject the mismatch.
  * DNS credentials are resolved per certificate: the inline Cloudflare token
    wins over CF_DNS_API_TOKEN; other Lego providers take their variables from
    dns.env (stored and redacted like any other inline secret).
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

from cryptography import x509

from . import certs, config
from .models import StepResult

log = logging.getLogger(__name__)

STEP = "issue"
LEGO_BIN = os.environ.get("LEGO_BIN", "lego")
RENEW_WINDOW_DAYS = int(os.environ.get("RENEW_WINDOW_DAYS") or 30)   # legacy constant; certs.due_for_renewal decides
CF_TOKEN_ENV = config.CF_TOKEN_ENV  # env var name Lego reads for the Cloudflare DNS-01 challenge
LEGO_TIMEOUT = int(os.environ.get("LEGO_TIMEOUT", "180"))

_ACME_URLS = {
    "letsencrypt": "https://acme-v02.api.letsencrypt.org/directory",
    "letsencrypt_test": "https://acme-staging-v02.api.letsencrypt.org/directory",
}


def issue_or_renew(cert, force: bool = False) -> StepResult:
    """Issue or renew the certificate (a Certificate, or the flattened ServerConfig).

    detail on success includes: renewed (bool), expiry (ISO str), serial (hex),
    and the three flattened file paths (cert/key/chain).
    """
    provider = (cert.dns_provider or "cloudflare").strip().lower()
    cf_token = config.cf_token_for(cert) if provider == "cloudflare" else ""
    if provider == "cloudflare" and not cf_token:
        return StepResult(
            step=STEP,
            ok=False,
            message=(f"No Cloudflare DNS token for {cert.id!r}: set it in the "
                     f"server's settings, or export {CF_TOKEN_ENV}."),
        )
    if provider != "cloudflare" and not cert.dns_env:
        return StepResult(
            step=STEP, ok=False,
            message=(f"DNS provider {provider!r} for {cert.id!r} has no credentials: add the provider's "
                     f"variables under DNS settings (see the Lego provider reference)."),
        )

    if not cert.acme_email:
        return StepResult(
            step=STEP,
            ok=False,
            message=f"acme.email is not set for server {cert.id!r}.",
        )

    if config.is_lab_ca(cert.acme_ca) and not config.lab_ca_available():
        return StepResult(
            step=STEP, ok=False,
            message=("The bundled lab CA is selected but is not configured: run "
                     "./setup.sh --with-ca --lab-domain <zone> (needs LAB_CA_HOST and the root at "
                     f"{config.LAB_CA_ROOT})."),
        )

    acme_url = _acme_url(cert)
    cert_dir = config.cert_dir_for(cert)                   # lego state + flattened files live here
    lego_cert = cert_dir / "certificates" / f"{cert.domain}.crt"

    first_issue = not lego_cert.exists()
    pre_mtime = lego_cert.stat().st_mtime if lego_cert.exists() else None
    on_disk = certs.leaf_info(cert_dir / f"{cert.domain}.cer") if not first_issue else dict(certs.ABSENT)

    if not force and not first_issue:
        due, why = certs.due_for_renewal(on_disk)
        if not due:
            # Nothing to do: keep the flattened files current and report without contacting the CA.
            leaf, key, chain = _flatten(cert_dir, cert.domain)
            expiry, serial = _read_cert(leaf)
            return StepResult(
                step=STEP, ok=True,
                message=f"Certificate for {cert.domain} still valid; no renewal needed ({why}).",
                detail={"renewed": False, "expiry": expiry, "serial": serial, "window": why,
                        "cert": str(leaf), "key": str(key), "chain": str(chain)},
            )
        log.info("renewal due for %s: %s", cert.domain, why)

    # Lego 5.x: `run` obtains or renews as needed; --renew-force makes it obtain
    # even when its own window would not trigger (the decision above is ours).
    cmd = [
        LEGO_BIN,
        "run",
        "--accept-tos",
        "--email", cert.acme_email,
        "--dns", provider,
        "--domains", cert.domain,
        "--key-type", cert.key_type,
        "--server", acme_url,
        "--path", str(cert_dir),
        "--no-random-sleep",
        "--ipv4only",
        "--dns.propagation.wait", os.environ.get("DNS_PROPAGATION_WAIT", "60s"),
        "--renew-force",
    ]
    configured_env = config.ca_environment(cert.acme_ca)
    if on_disk.get("present") and on_disk.get("environment") and on_disk["environment"] != configured_env:
        # The CA would reject an ARI "replaces" link to a certificate it did not issue.
        cmd.append("--ari-disable")
        log.info("ARI disabled for %s: certificate on disk is %s, configured CA is %s",
                 cert.domain, on_disk["environment"], configured_env)
    action = "issue" if (force or first_issue) else "renew"

    env = lego_environment(cert, cf_token)

    log.info("lego %s for %s (%s)", action, cert.domain, acme_url)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=LEGO_TIMEOUT)
    except subprocess.TimeoutExpired:
        log.error("lego %s timed out after %ss for %s", action, LEGO_TIMEOUT, cert.domain)
        return StepResult(
            step=STEP,
            ok=False,
            message=f"lego {action} timed out after {LEGO_TIMEOUT}s (DNS challenge likely stuck)",
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
    leaf, key, chain = _flatten(cert_dir, cert.domain)
    expiry, serial = _read_cert(leaf)

    msg = (f"Certificate {action}d for {cert.domain} (expires {expiry})."
           if renewed else
           f"Certificate for {cert.domain} still valid; no renewal needed.")

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


def _acme_url(cert) -> str:
    ca = (cert.acme_ca or "letsencrypt").strip()
    if config.is_lab_ca(ca):
        return config.lab_ca_acme_url()
    return ca if ca.startswith("http") else _ACME_URLS.get(ca, _ACME_URLS["letsencrypt"])


def lego_environment(cert, cf_token: str) -> dict[str, str]:
    """Environment for the Lego subprocess: DNS credentials plus, for the bundled
    lab CA, the root certificate Lego must trust when talking to the directory."""
    env = os.environ.copy()
    if (cert.dns_provider or "cloudflare").strip().lower() == "cloudflare":
        env[CF_TOKEN_ENV] = cf_token
    for k, v in (getattr(cert, "dns_env", None) or {}).items():
        if k and v:
            env[k] = v
    if config.is_lab_ca(cert.acme_ca):
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
