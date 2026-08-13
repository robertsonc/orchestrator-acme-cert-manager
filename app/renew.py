"""Orchestrate issue -> deploy -> restart and record the outcome."""
from __future__ import annotations

import datetime
import logging
from pathlib import Path

from cryptography import x509

from . import config, deploy, issue, notify, restart, store
from .models import RenewalRecord, ServerConfig

log = logging.getLogger("renew")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _leaf_meta(leaf: Path) -> tuple[str | None, str | None]:
    """(expiry_iso, serial_hex) for a leaf cert on disk, or (None, None)."""
    if not leaf.exists():
        return None, None
    try:
        cert = x509.load_pem_x509_certificate(leaf.read_bytes())
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        return na.isoformat(), format(cert.serial_number, "x")
    except Exception as exc:  # noqa: BLE001
        log.warning("could not read leaf cert %s: %s", leaf, exc)
        return None, None


def renew_server(server: ServerConfig, force: bool = False) -> RenewalRecord:
    """Run the full pipeline for one server, short-circuiting on the first failure.

    Skips deploy+restart when issuance reports the cert was not actually renewed
    (and we are not forcing) -- the Orchestrator is only restarted when the cert
    genuinely changed.
    """
    steps = []
    outcome = "success"

    r_issue = issue.issue_or_renew(server, force=force)
    steps.append(r_issue.as_dict())
    not_after = r_issue.detail.get("expiry")
    serial = r_issue.detail.get("serial")

    if not r_issue.ok:
        outcome = "failed"
    elif not force and not r_issue.detail.get("renewed", True):
        outcome = "skipped"
        log.info("renew_server(%s): skipped (cert still valid)", server.id)

    if outcome == "success":
        r_deploy = deploy.deploy(server)
        steps.append(r_deploy.as_dict())
        if not r_deploy.ok:
            outcome = "failed"

    if outcome == "success":
        r_restart = restart.restart(server)
        steps.append(r_restart.as_dict())
        if not r_restart.ok:
            outcome = "failed"

    record = RenewalRecord(
        server_id=server.id,
        timestamp=_now(),
        outcome=outcome,
        steps=steps,
        not_after=not_after,
        serial=serial,
    )
    store.add_record(record)
    notify.send(record)
    log.info("renew_server(%s): %s", server.id, outcome)
    return record


def redeploy_server(server: ServerConfig) -> RenewalRecord:
    """Re-deploy the certificate already on disk (deploy -> restart), skipping issuance.

    Never contacts the ACME CA, so it is immune to Let's Encrypt rate limits. Use
    it to re-push a known-good cert to the Orchestrator (e.g. after an appliance
    was rebuilt) or to re-run activation without spending an issuance. Records to
    history and alerts on failure exactly like renew_server; the restart step still
    handles served-cert verification and rollback to the last-known-good cert.
    """
    leaf = config.cert_dir_for(server) / f"{server.domain}.cer"
    not_after, serial = _leaf_meta(leaf)

    if not leaf.exists():
        r = deploy.StepResult(
            "deploy", ok=False,
            message="no certificate on disk yet -- run Force renew first",
        )
        record = RenewalRecord(server_id=server.id, timestamp=_now(), outcome="failed",
                               steps=[r.as_dict()], not_after=None, serial=None)
        store.add_record(record)
        notify.send(record)
        log.info("redeploy_server(%s): no cert on disk", server.id)
        return record

    steps = []
    outcome = "success"

    r_deploy = deploy.deploy(server)
    steps.append(r_deploy.as_dict())
    if not r_deploy.ok:
        outcome = "failed"

    if outcome == "success":
        r_restart = restart.restart(server)
        steps.append(r_restart.as_dict())
        if not r_restart.ok:
            outcome = "failed"

    record = RenewalRecord(
        server_id=server.id,
        timestamp=_now(),
        outcome=outcome,
        steps=steps,
        not_after=not_after,
        serial=serial,
    )
    store.add_record(record)
    notify.send(record)
    log.info("redeploy_server(%s): %s", server.id, outcome)
    return record


def renew_all(force: bool = False) -> list[RenewalRecord]:
    servers = config.load_servers()
    if not servers:
        log.warning("no servers configured")
        return []
    return [renew_server(s, force=force) for s in servers]
