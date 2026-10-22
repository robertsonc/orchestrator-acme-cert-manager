"""Orchestrate issue -> (deploy -> activate per target) and record the outcome.

One certificate is issued once and then deployed to each of its targets by
the target's driver. A run holds the certificate's lock (app/locks.py) so the
scheduler and the web UI never work on the same certificate at once; the
record carries who started it (actor) and from where (source).

``renew_server`` / ``redeploy_server`` keep the original one-Orchestrator
signatures: they wrap the certificate that server entry represents.
"""
from __future__ import annotations

import datetime
import logging
import time
from pathlib import Path

from cryptography import x509

from . import config, deploy, drivers, issue, locks, notify, restart, store  # noqa: F401 (deploy/restart patched by tests)
from .drivers.base import CertBundle
from .models import Certificate, RenewalRecord, ServerConfig, StepResult, Target

log = logging.getLogger("renew")


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")


def _timed(fn, arg) -> dict:
    """Run a pipeline step and return its dict with elapsed_s added."""
    t0 = time.monotonic()
    res = fn(arg)
    d = res.as_dict()
    d["elapsed_s"] = round(time.monotonic() - t0, 1)
    return d


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


def _deploy_targets(cert: Certificate, targets: list[Target], steps: list[dict]) -> str:
    """deploy -> activate for each target in order; stops at the first failure."""
    bundle = CertBundle.for_certificate(cert)
    for t in targets:
        drv = drivers.get(t.driver)
        s_deploy = _timed(lambda _t: drv.deploy(_t, bundle), t)
        s_deploy["target"] = t.id
        steps.append(s_deploy)
        if not s_deploy["ok"]:
            return "failed"
        s_act = _timed(lambda _t: drv.activate_step(_t, bundle), t)
        s_act["target"] = t.id
        steps.append(s_act)
        if not s_act["ok"]:
            return "failed"
    return "success"


def _finish(cert: Certificate, targets: list[Target], steps: list[dict], outcome: str, kind: str,
            not_after, serial, t_start: float, actor: str, source: str) -> RenewalRecord:
    record = RenewalRecord(
        server_id=cert.id, timestamp=_now(), outcome=outcome, steps=steps,
        not_after=not_after, serial=serial, kind=kind,
        elapsed_s=round(time.monotonic() - t_start, 1),
        actor=actor, source=source, targets=[t.id for t in targets],
    )
    store.add_record(record)
    notify.send(record)
    return record


def renew_certificate(cert: Certificate, force: bool = False, actor: str = "", source: str = "",
                      targets: list[Target] | None = None) -> RenewalRecord:
    """Run the full pipeline for one certificate, short-circuiting on the first failure.

    Skips deploy+activate when issuance reports the cert was not actually renewed
    (and we are not forcing): targets are only touched when the cert changed.
    Raises locks.RunLocked when another run holds this certificate.
    """
    kind = "renew" if force else "scheduled"
    targets = list(targets if targets is not None else cert.targets)
    with locks.run_lock(cert.id, kind, actor, source):
        steps: list[dict] = []
        outcome = "success"
        t_start = time.monotonic()

        s_issue = _timed(lambda c: issue.issue_or_renew(c, force=force), cert)
        steps.append(s_issue)
        not_after = s_issue["detail"].get("expiry")
        serial = s_issue["detail"].get("serial")

        if not s_issue["ok"]:
            outcome = "failed"
        elif not force and not s_issue["detail"].get("renewed", True):
            outcome = "skipped"
            log.info("renew(%s): skipped (cert still valid)", cert.id)

        if outcome == "success":
            outcome = _deploy_targets(cert, targets, steps)

        record = _finish(cert, targets, steps, outcome, kind, not_after, serial, t_start, actor, source)
    log.info("renew(%s): %s", cert.id, outcome)
    return record


def redeploy_certificate(cert: Certificate, actor: str = "", source: str = "",
                         targets: list[Target] | None = None) -> RenewalRecord:
    """Re-deploy the certificate already on disk (deploy -> activate), skipping issuance.

    Never contacts the ACME CA, so it is immune to Let's Encrypt rate limits. Use
    it to re-push a known-good cert to a target (e.g. after an appliance was
    rebuilt) or to re-run activation without spending an issuance. Records to
    history and alerts on failure exactly like renew_certificate.
    """
    targets = list(targets if targets is not None else cert.targets)
    leaf = config.cert_dir_for(cert) / f"{cert.domain}.cer"
    not_after, serial = _leaf_meta(leaf)
    with locks.run_lock(cert.id, "redeploy", actor, source):
        t_start = time.monotonic()
        if not leaf.exists():
            r = StepResult("deploy", ok=False, message="no certificate on disk yet -- run Force renew first")
            record = _finish(cert, targets, [r.as_dict()], "failed", "redeploy", None, None, t_start, actor, source)
            log.info("redeploy(%s): no cert on disk", cert.id)
            return record
        steps: list[dict] = []
        outcome = _deploy_targets(cert, targets, steps)
        record = _finish(cert, targets, steps, outcome, "redeploy", not_after, serial, t_start, actor, source)
    log.info("redeploy(%s): %s", cert.id, outcome)
    return record


# --------------------------------------------------------------------------- legacy entry points

def renew_server(server: ServerConfig, force: bool = False, actor: str = "", source: str = "") -> RenewalRecord:
    """Full pipeline for the certificate this Orchestrator entry represents."""
    return renew_certificate(server.to_certificate(), force=force, actor=actor, source=source)


def redeploy_server(server: ServerConfig, actor: str = "", source: str = "") -> RenewalRecord:
    """deploy -> activate from the certificate on disk for this Orchestrator entry."""
    return redeploy_certificate(server.to_certificate(), actor=actor, source=source)


def renew_all(force: bool = False, actor: str = "scheduler", source: str = "cron") -> list[RenewalRecord]:
    """What the scheduler runs: every certificate, each under its own lock.

    A certificate whose lock is held (a Force renew from the UI, say) is skipped
    with a warning rather than queued: the next scheduled run picks it up.
    """
    certs = config.load_certificates()
    if source == "cron":
        store.scheduler_started(source)
    if not certs:
        log.warning("no certificates configured")
        if source == "cron":
            store.scheduler_finished({})
        return []
    records: list[RenewalRecord] = []
    outcomes: dict[str, str] = {}
    for c in certs:
        try:
            rec = renew_certificate(c, force=force, actor=actor, source=source)
        except locks.RunLocked as exc:
            log.warning("renew-all: %s", exc)
            outcomes[c.id] = "locked"
            continue
        records.append(rec)
        outcomes[c.id] = rec.outcome
    if source == "cron":
        store.scheduler_finished(outcomes)
    return records
