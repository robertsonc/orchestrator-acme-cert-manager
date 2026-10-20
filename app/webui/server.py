"""Web UI: dashboard, renewal history, force-renew / force-deploy, server management,
SSH connection test, and a system/preflight panel."""
from __future__ import annotations

import datetime
import logging
import re
import ssl
import threading
import time

from flask import Flask, abort, jsonify, make_response, redirect, render_template, request, url_for

from .. import config, preflight, sshcheck, store
from . import auth

log = logging.getLogger("webui")
app = Flask(__name__)

# Endpoints reachable without a session: the auth pages, static assets, health.
_OPEN_ENDPOINTS = {"login", "setup", "logout", "healthz", "static"}


def _current_user() -> str | None:
    return auth.read_token(request.cookies.get(auth.COOKIE_NAME, ""))


def _set_session(resp, username: str):
    resp.set_cookie(
        auth.COOKIE_NAME, auth.make_token(username),
        max_age=auth.SESSION_TTL, httponly=True, samesite="Lax",
    )
    return resp


@app.context_processor
def _inject_user():
    return {"current_user": _current_user(), "relative_time": relative_time}


@app.before_request
def _gate():
    """Require login on everything except the open endpoints.

    If no admin exists yet, force the first-run Setup flow instead.
    """
    if request.endpoint in _OPEN_ENDPOINTS:
        return None
    if auth.needs_setup():
        return redirect(url_for("setup"))
    if not _current_user():
        return redirect(url_for("login", next=request.path))
    return None


@app.route("/healthz")
def healthz():
    return {"status": "ok"}, 200


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if not auth.needs_setup():
        return redirect(url_for("login"))
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        p2 = request.form.get("confirm", "")
        errors = []
        if not u:
            errors.append("A username is required.")
        if len(p) < auth.MIN_PASSWORD_LEN:
            errors.append(f"Password must be at least {auth.MIN_PASSWORD_LEN} characters.")
        if p != p2:
            errors.append("The two passwords don't match.")
        if errors:
            return render_template("setup.html", errors=errors, username=u, now=_now()), 400
        auth.create_admin(u, p)
        log.info("admin account %r created", u)
        return _set_session(make_response(redirect(url_for("index"))), u)
    return render_template("setup.html", errors=[], username="", now=_now())


@app.route("/login", methods=["GET", "POST"])
def login():
    if auth.needs_setup():
        return redirect(url_for("setup"))
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        if auth.verify(u, p):
            nxt = request.form.get("next", "") or url_for("index")
            if not nxt.startswith("/") or nxt.startswith("//"):
                nxt = url_for("index")
            return _set_session(make_response(redirect(nxt)), u)
        return render_template("login.html", error="Incorrect username or password.",
                               next=request.form.get("next", ""), now=_now()), 401
    return render_template("login.html", error=None, next=request.args.get("next", ""), now=_now())


@app.route("/logout")
def logout():
    resp = make_response(redirect(url_for("login")))
    resp.delete_cookie(auth.COOKIE_NAME)
    return resp


CA_CHOICES = [
    ("letsencrypt", "Let's Encrypt (production)"),
    ("letsencrypt_test", "Let's Encrypt (staging)"),
    (config.LAB_CA_ID, "Lab CA (bundled step-ca)"),
]
KEY_CHOICES = ["rsa2048", "rsa3072", "rsa4096"]
_ALLOWED_CA = {v for v, _ in CA_CHOICES}
_ALLOWED_KEY = set(KEY_CHOICES)
_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

_IN_PROGRESS: set[str] = set()
_PROGRESS_LOCK = threading.Lock()

_SERVED_TTL = 60          # seconds to cache the certificate served on :443
_SERVED_TIMEOUT = 5
_SERVED_CACHE: dict[str, tuple[float, dict]] = {}
_SERVED_LOCK = threading.Lock()


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def _is_renewing(server_id: str) -> bool:
    with _PROGRESS_LOCK:
        return server_id in _IN_PROGRESS


# ============================= certificate state =============================
def environment_of(issuer: str | None) -> str | None:
    """'lab' / 'staging' / 'production' from an issuer DN, or None if unknown."""
    if not issuer:
        return None
    if issuer in config.lab_ca_issuer_names():
        return "lab"
    up = issuer.upper()
    if "STAGING" in up or "FAKE" in up or "ERSATZ" in up:
        return "staging"
    return "production"


def _parse_cert(pem: bytes) -> dict:
    from cryptography import x509  # lazy import
    cert = x509.load_pem_x509_certificate(pem)
    na = cert.not_valid_after_utc
    issuer = cert.issuer.rfc4514_string()
    return {
        "present": True,
        "not_after": na.strftime("%Y-%m-%d"),
        "days_left": (na - datetime.datetime.now(datetime.timezone.utc)).days,
        "serial": format(cert.serial_number, "X"),
        "issuer": issuer,
        "environment": environment_of(issuer),
    }


def _cert_info(server) -> dict:
    """The *issued* certificate: what is stored locally for this server."""
    cert_path = config.leaf_path_for(server)
    info = {"present": False, "not_after": None, "days_left": None, "serial": None,
            "issuer": None, "environment": None}
    if not cert_path.exists():
        return info
    try:
        info.update(_parse_cert(cert_path.read_bytes()))
    except Exception as exc:  # noqa: BLE001
        log.warning("cert parse failed for %s: %s", server.id, exc)
    return info


def _fetch_served(host: str, port: int = 443) -> dict:
    """The certificate the appliance actually presents on TCP/443 (no chain validation)."""
    try:
        pem = ssl.get_server_certificate((host, port), timeout=_SERVED_TIMEOUT)
        info = _parse_cert(pem.encode())
        info["error"] = None
        return info
    except (ssl.SSLError, OSError, ValueError) as exc:
        return {"present": False, "serial": None, "issuer": None, "environment": None,
                "not_after": None, "days_left": None, "error": str(exc) or exc.__class__.__name__}


def _served_info(server) -> dict:
    key = f"{server.orchestrator_host}:443"
    now = time.monotonic()
    with _SERVED_LOCK:
        hit = _SERVED_CACHE.get(key)
        if hit and now - hit[0] < _SERVED_TTL:
            return hit[1]
    info = _fetch_served(server.orchestrator_host)
    with _SERVED_LOCK:
        _SERVED_CACHE[key] = (now, info)
    return info


def invalidate_served_cache() -> None:
    with _SERVED_LOCK:
        _SERVED_CACHE.clear()


def lifecycle(server, issued: dict, served: dict) -> dict:
    """Activation state: does the appliance serve the certificate we issued?"""
    configured_env = config.ca_environment(server.acme_ca)
    if not issued.get("present"):
        return {"state": "none", "configured_env": configured_env,
                "message": "No certificate issued yet — run Force renew."}
    if served.get("error") or not served.get("present"):
        return {"state": "unknown", "configured_env": configured_env,
                "message": f"Could not read the certificate served on {server.orchestrator_host}:443 "
                           f"({served.get('error') or 'no certificate'})."}
    if served.get("serial") == issued.get("serial"):
        msg = "The issued certificate is live on the appliance."
        ienv = issued.get("environment")
        if ienv and ienv != configured_env:
            msg += (f" It was issued by the {ienv.upper()} CA while the server is set to "
                    f"{configured_env} — run Force renew to issue from the configured CA.")
        return {"state": "live", "configured_env": configured_env, "message": msg}
    ienv = (issued.get("environment") or "unknown").capitalize()
    senv = served.get("environment") or "a different"
    return {"state": "pending", "configured_env": configured_env,
            "message": (f"{ienv} certificate issued (serial {issued.get('serial')}). "
                        f"Orchestrator is still serving {senv} certificate "
                        f"(serial {served.get('serial')}). Deployment or activation is pending — "
                        f"use Force deploy (no CA contact).")}


def _parse_ts(ts: str | None):
    if not ts:
        return None
    try:
        d = datetime.datetime.fromisoformat(ts)
        if d.tzinfo is None:
            d = d.replace(tzinfo=datetime.timezone.utc)
        return d
    except ValueError:
        return None


def relative_time(ts: str | None) -> str:
    d = _parse_ts(ts)
    if d is None:
        return "—"
    secs = int((datetime.datetime.now(datetime.timezone.utc) - d).total_seconds())
    if secs < 0:
        return "just now"
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if secs >= size:
            return f"{secs // size}{unit} ago"
    return f"{secs}s ago"


def health(row: dict) -> dict:
    """One roll-up state per server, with the reasons behind it.

    States, worst first: working, critical, warning, ok, unknown, none.
    Status colors never carry meaning alone: the template pairs each state
    with a glyph and the label.
    """
    reasons: list[str] = []
    cert, lc, last = row["cert"], row["lifecycle"], row["last"]
    if row["renewing"]:
        return {"state": "working", "label": "working", "reasons": ["a run is in progress"]}
    if row["ssh_problems"]:
        reasons.append("SSH configuration invalid")
    if cert.get("present") and cert.get("days_left") is not None and cert["days_left"] <= 0:
        reasons.append("certificate expired")
    if last and last.get("outcome") == "failed":
        reasons.append("last run failed")
    if reasons:
        return {"state": "critical", "label": "attention", "reasons": reasons}
    if lc["state"] == "pending":
        reasons.append("issued certificate not yet served")
    if cert.get("present") and cert.get("days_left") is not None and cert["days_left"] <= 30:
        reasons.append(f"expires in {cert['days_left']} days")
    if cert.get("environment") and cert["environment"] != lc["configured_env"]:
        reasons.append(f"{cert['environment']} certificate while configured for {lc['configured_env']}")
    if cert.get("environment") == "staging" and lc["state"] == "live":
        reasons.append("serving a staging certificate")
    if reasons:
        return {"state": "warning", "label": "warning", "reasons": reasons}
    if not cert.get("present"):
        return {"state": "none", "label": "no certificate", "reasons": ["nothing issued yet"]}
    if lc["state"] == "unknown":
        return {"state": "unknown", "label": "unverified", "reasons": [lc["message"]]}
    return {"state": "ok", "label": "healthy", "reasons": ["issued certificate is live"]}


def _summarize(record: dict | None) -> dict | None:
    if not record:
        return None
    steps = record.get("steps", []) or []
    outcome = record.get("outcome")
    rolled_back = any((s.get("detail") or {}).get("rolled_back") for s in steps)
    failed_step = None
    if outcome == "failed":
        bad = next((s for s in steps if not s.get("ok", True)), None)
        message = (bad or {}).get("message", "")
        if bad:
            failed_step = {"step": bad.get("step"), "detail": bad.get("detail") or {}}
    elif steps:
        message = steps[-1].get("message", "")
    else:
        message = ""
    return {
        "server_id": record.get("server_id"), "outcome": outcome,
        "timestamp": record.get("timestamp"), "ago": relative_time(record.get("timestamp")),
        "steps": steps, "message": message,
        "rolled_back": rolled_back, "not_after": record.get("not_after"),
        "serial": record.get("serial"), "failed_step": failed_step,
        "kind": record.get("kind") or "renew", "elapsed_s": record.get("elapsed_s"),
    }


def _row_for(s, with_served: bool = True) -> dict:
    issued = _cert_info(s)
    served = _served_info(s) if with_served else {"present": False, "error": "not checked"}
    row = {
        "id": s.id, "name": s.name, "domain": s.domain,
        "host": s.orchestrator_host, "ca": s.acme_ca,
        "ca_env": config.ca_environment(s.acme_ca),
        "verify_ssl": s.verify_ssl, "ca_bundle": s.ca_bundle,
        "ssh_user": s.ssh_user, "ssh_key_path": s.ssh_key_path,
        "ssh_known_hosts": s.ssh_known_hosts, "ssh_port": s.ssh_port,
        "restart_command": s.restart_command, "nginx_reload_command": s.nginx_reload_command,
        "key_type": s.key_type, "acme_email": s.acme_email,
        "secrets": {"cf_inline": bool(s.dns_api_token), "api_inline": bool(s.api_key),
                    "api_key_env": s.api_key_env},
        "cert": issued, "served": served, "lifecycle": lifecycle(s, issued, served),
        "ssh_problems": sshcheck.validate(s),
        "last": _summarize(store.latest_for(s.id)),
        "renewing": _is_renewing(s.id),
    }
    row["health"] = health(row)
    return row


def _rows(with_served: bool = True) -> list[dict]:
    return [_row_for(s, with_served) for s in config.load_servers()]


_HEALTH_ORDER = {"working": 0, "critical": 1, "warning": 2, "unknown": 3, "none": 4, "ok": 5}


def fleet_summary(rows: list[dict]) -> dict:
    """Counts for the overview tiles."""
    return {
        "servers": len(rows),
        "healthy": sum(1 for r in rows if r["health"]["state"] == "ok"),
        "attention": sum(1 for r in rows if r["health"]["state"] in ("critical", "warning")),
        "expiring": sum(1 for r in rows if r["cert"].get("present")
                        and r["cert"].get("days_left") is not None and r["cert"]["days_left"] <= 30),
        "working": sum(1 for r in rows if r["renewing"]),
        "min_days": min((r["cert"]["days_left"] for r in rows
                         if r["cert"].get("present") and r["cert"].get("days_left") is not None),
                        default=None),
    }


def _system() -> dict:
    rep = preflight.run(strict=False)
    d = rep.as_dict()
    d["problems"] = [f.as_dict() for f in rep.findings if f.level in ("fatal", "warn")]
    d["lab_ca"] = {"configured": config.lab_ca_available(), "host": config.LAB_CA_HOST,
                   "url": config.lab_ca_base_url(),
                   "fingerprint": config.lab_ca_root_fingerprint() if config.LAB_CA_ROOT.is_file() else ""}
    return d


# ============================= dashboard =====================================
def _fleet_context() -> dict:
    rows = sorted(_rows(), key=lambda r: (_HEALTH_ORDER.get(r["health"]["state"], 9), r["name"].lower()))
    history = [_summarize(r) for r in store.all_records()[:20]]
    return {"rows": rows, "summary": fleet_summary(rows), "history": history,
            "system": _system(), "busy": any(r["renewing"] for r in rows), "now": _now(),
            "updated": datetime.datetime.now().strftime("%H:%M:%S")}


@app.route("/")
def index():
    return render_template("index.html", **_fleet_context())


@app.route("/partials/fleet")
def partial_fleet():
    """Live-refresh fragment for the overview (swapped in by app.js)."""
    return render_template("_fleet.html", **_fleet_context())


def _server_context(server_id: str) -> dict:
    try:
        s = config.get_server(server_id)
    except config.ConfigError:
        abort(404)
    row = _row_for(s)
    history = [_summarize(r) for r in store.all_records() if r.get("server_id") == server_id][:30]
    return {"r": row, "history": history, "system": _system(), "busy": row["renewing"],
            "now": _now(), "updated": datetime.datetime.now().strftime("%H:%M:%S")}


@app.route("/server/<server_id>")
def server_detail(server_id: str):
    return render_template("server.html", test_result=None, **_server_context(server_id))


@app.route("/partials/server/<server_id>")
def partial_server(server_id: str):
    return render_template("_server.html", test_result=None, **_server_context(server_id))


@app.route("/server/<server_id>/test-ssh", methods=["POST"])
def server_test_ssh(server_id: str):
    """Authenticate over SSH and probe sudo authorization. Restarts nothing."""
    try:
        s = config.get_server(server_id)
    except config.ConfigError:
        abort(404)
    res = sshcheck.test_connection(s)
    log.info("ssh-test %s via web UI: %s", s.id, "ok" if res.ok else res.message)
    return render_template("server.html", test_result=res.as_dict(), **_server_context(server_id))


@app.route("/api/servers")
def api_servers():
    return jsonify(_rows())


@app.route("/api/server/<server_id>")
def api_server(server_id: str):
    ctx = _server_context(server_id)
    return jsonify({"server": ctx["r"], "history": ctx["history"]})


@app.route("/api/history")
def api_history():
    return jsonify([_summarize(r) for r in store.all_records()])


@app.route("/api/status")
def api_status():
    return jsonify(_system())


def _run_in_background(server_id: str, fn, label: str):
    with _PROGRESS_LOCK:
        _IN_PROGRESS.add(server_id)

    def _run():
        try:
            server = config.get_server(server_id)
            fn(server)
        except Exception as exc:  # noqa: BLE001
            log.error("%s failed for %s: %s", label, server_id, exc)
        finally:
            invalidate_served_cache()
            with _PROGRESS_LOCK:
                _IN_PROGRESS.discard(server_id)

    threading.Thread(target=_run, daemon=True).start()


@app.route("/renew/<server_id>", methods=["POST"])
def renew(server_id: str):
    """Force renew: full pipeline, contacts the ACME CA."""
    from .. import renew as renew_mod
    _run_in_background(server_id, lambda s: renew_mod.renew_server(s, force=True), "force renew")
    return redirect(_back(server_id))


@app.route("/deploy/<server_id>", methods=["POST"])
def force_deploy(server_id: str):
    """Force deploy: re-push the on-disk cert (deploy -> restart), skipping issuance. No CA contact."""
    from .. import renew as renew_mod
    _run_in_background(server_id, renew_mod.redeploy_server, "force deploy")
    return redirect(_back(server_id))


def _back(server_id: str) -> str:
    """Return to the server page when the action came from it, else the overview."""
    ref = request.form.get("return", "")
    if ref == "server":
        return url_for("server_detail", server_id=server_id)
    return url_for("index")


# ============================= settings ======================================
def _flat_from_server(s) -> dict:
    # Secret fields are intentionally blank here — a stored secret is NEVER
    # echoed back to the browser. The template shows a "stored" hint instead.
    return {
        "id": s.id, "name": s.name, "orchestrator_host": s.orchestrator_host,
        "domain": s.domain, "verify_ssl": s.verify_ssl, "ca_bundle": s.ca_bundle,
        "acme_ca": s.acme_ca, "acme_email": s.acme_email, "key_type": s.key_type,
        "dns_provider": s.dns_provider, "dns_api_token": "", "ssh_user": s.ssh_user,
        "ssh_key_path": s.ssh_key_path, "ssh_known_hosts": s.ssh_known_hosts,
        "ssh_port": s.ssh_port, "restart_command": s.restart_command,
        "nginx_reload_command": s.nginx_reload_command,
        "api_key_env": s.api_key_env, "api_key": "",
    }


def _flat_blank() -> dict:
    return {
        "id": "", "name": "", "orchestrator_host": "", "domain": "", "verify_ssl": False,
        "ca_bundle": "", "acme_ca": "letsencrypt_test", "acme_email": "", "key_type": "rsa2048",
        "dns_provider": "cloudflare", "dns_api_token": "", "ssh_user": "",
        "ssh_key_path": config.DEFAULT_SSH_KEY, "ssh_known_hosts": config.DEFAULT_KNOWN_HOSTS,
        "ssh_port": 22, "restart_command": config.DEFAULT_RESTART_COMMAND,
        "nginx_reload_command": config.DEFAULT_NGINX_RELOAD_COMMAND,
        "api_key_env": "ORCH_API_KEY", "api_key": "",
    }


def _flat_from_request(f) -> dict:
    host = f.get("orchestrator_host", "").strip()
    return {
        "id": f.get("id", "").strip(),
        "name": f.get("name", "").strip(),
        "orchestrator_host": host,
        "domain": f.get("domain", "").strip() or host,
        "verify_ssl": f.get("verify_ssl") == "on",
        "ca_bundle": f.get("ca_bundle", "").strip(),
        "acme_ca": f.get("acme_ca", "letsencrypt").strip(),
        "acme_email": f.get("acme_email", "").strip(),
        "key_type": f.get("key_type", "rsa2048").strip(),
        "dns_provider": f.get("dns_provider", "cloudflare").strip() or "cloudflare",
        "dns_api_token": f.get("dns_api_token", "").strip(),
        "ssh_user": f.get("ssh_user", "").strip(),
        "ssh_key_path": f.get("ssh_key_path", "").strip(),
        "ssh_known_hosts": f.get("ssh_known_hosts", "").strip() or config.DEFAULT_KNOWN_HOSTS,
        "ssh_port": f.get("ssh_port", "22").strip() or "22",
        "restart_command": f.get("restart_command", "").strip(),
        "nginx_reload_command": f.get("nginx_reload_command", "").strip(),
        "api_key_env": f.get("api_key_env", "ORCH_API_KEY").strip() or "ORCH_API_KEY",
        "api_key": f.get("api_key", "").strip(),
    }


def _nest(flat: dict) -> dict:
    return {
        "id": flat["id"], "name": flat["name"] or flat["id"],
        "orchestrator_host": flat["orchestrator_host"], "domain": flat["domain"],
        "api_key_env": flat["api_key_env"], "api_key": flat["api_key"],
        "verify_ssl": flat["verify_ssl"], "ca_bundle": flat["ca_bundle"],
        "acme": {"ca": flat["acme_ca"], "email": flat["acme_email"], "key_type": flat["key_type"]},
        "dns": {"provider": flat["dns_provider"], "api_token": flat["dns_api_token"]},
        "ssh": {
            "user": flat["ssh_user"], "key_path": flat["ssh_key_path"],
            "known_hosts": flat["ssh_known_hosts"], "port": flat["ssh_port"],
            "restart_command": flat["restart_command"],
            "nginx_reload_command": flat["nginx_reload_command"],
        },
    }


def _validate(flat: dict, is_new: bool) -> list[str]:
    errors = []
    sid = flat["id"]
    if not sid:
        errors.append("ID is required.")
    elif not _ID_RE.match(sid):
        errors.append("ID may contain only letters, numbers, hyphens, and underscores.")
    elif is_new and config.server_exists(sid):
        errors.append(f"A server with ID '{sid}' already exists.")
    if not flat["orchestrator_host"]:
        errors.append("Orchestrator host is required.")
    if not flat["acme_email"]:
        errors.append("ACME email is required — Let's Encrypt needs it for registration.")
    if flat["acme_ca"] not in _ALLOWED_CA:
        errors.append("Invalid certificate authority selection.")
    elif config.is_lab_ca(flat["acme_ca"]) and not config.lab_ca_available():
        errors.append("The bundled lab CA is not configured on this host: run ./setup.sh --with-ca "
                      "--lab-domain <zone>, then select it.")
    if flat["key_type"] not in _ALLOWED_KEY:
        errors.append("Invalid key type.")
    try:
        port = int(flat["ssh_port"])
        if not (1 <= port <= 65535):
            errors.append("SSH port must be between 1 and 65535.")
    except (TypeError, ValueError):
        errors.append("SSH port must be a number.")
        return errors
    if flat["ca_bundle"]:
        from pathlib import Path
        if not Path(flat["ca_bundle"]).is_file():
            errors.append(f"CA bundle not found at {flat['ca_bundle']} (path inside the container).")
    if flat["orchestrator_host"]:
        try:
            candidate = config.server_from_dict(_nest(flat))
        except config.ConfigError as exc:
            errors.append(str(exc))
        else:
            errors.extend(f"SSH: {p}" for p in sshcheck.validate(candidate))
    return errors


def _render_form(flat, errors, is_new, existing=None, status=200):
    return render_template(
        "server_form.html", form=flat, errors=errors, is_new=is_new,
        ca_choices=CA_CHOICES, key_choices=KEY_CHOICES,
        cf_token_set=bool(existing and existing.dns_api_token),
        api_key_set=bool(existing and existing.api_key),
        default_key=config.DEFAULT_SSH_KEY, default_known_hosts=config.DEFAULT_KNOWN_HOSTS,
        now=_now(),
    ), status


def _render_settings(test_result=None, test_server=None, status=200):
    return render_template("settings.html", servers=config.load_servers(),
                           ca_labels=dict(CA_CHOICES), system=_system(),
                           test_result=test_result, test_server=test_server, now=_now()), status


@app.route("/settings")
def settings():
    return _render_settings()[0]


@app.route("/settings/test-ssh/<server_id>", methods=["POST"])
def settings_test_ssh(server_id: str):
    """Authenticate over SSH and probe sudo authorization. Restarts nothing."""
    try:
        s = config.get_server(server_id)
    except config.ConfigError:
        return redirect(url_for("settings"))
    return server_test_ssh(server_id)


@app.route("/settings/new")
def settings_new():
    return _render_form(_flat_blank(), [], is_new=True)[0]


@app.route("/settings/edit/<server_id>")
def settings_edit(server_id: str):
    try:
        s = config.get_server(server_id)
    except config.ConfigError:
        return redirect(url_for("settings"))
    return _render_form(_flat_from_server(s), [], is_new=False, existing=s)[0]


@app.route("/settings/save", methods=["POST"])
def settings_save():
    original_id = request.form.get("original_id", "").strip()
    is_new = original_id == ""
    flat = _flat_from_request(request.form)

    existing = None
    if not is_new:
        flat["id"] = original_id  # id is create-only; never rename on edit
        try:
            existing = config.get_server(original_id)
        except config.ConfigError:
            existing = None

    errors = _validate(flat, is_new)
    if errors:
        return _render_form(flat, errors, is_new, existing=existing, status=400)

    # Keep existing secrets when the field is left blank on edit; a typed value replaces.
    if existing is not None:
        if not flat["dns_api_token"]:
            flat["dns_api_token"] = existing.dns_api_token
        if not flat["api_key"]:
            flat["api_key"] = existing.api_key

    server = config.server_from_dict(_nest(flat))
    config.upsert_server(server)
    log.info("server %s saved via web UI to %s", server.id, config.SERVERS_FILE)
    return redirect(url_for("settings"))


@app.route("/settings/delete/<server_id>", methods=["POST"])
def settings_delete(server_id: str):
    if config.delete_server(server_id):
        log.info("server %s deleted via web UI", server_id)
    return redirect(url_for("settings"))


def main() -> None:
    logging.basicConfig(level="INFO", format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    log.info("web UI starting; configuration file: %s", config.SERVERS_FILE)
    app.run(host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
