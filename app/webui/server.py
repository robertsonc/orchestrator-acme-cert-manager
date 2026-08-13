"""Web UI: dashboard, renewal history, force-renew, and server management."""
from __future__ import annotations

import datetime
import logging
import re
import threading

from flask import Flask, jsonify, make_response, redirect, render_template, request, url_for

from .. import config, store
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
    return {"current_user": _current_user()}


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
            if not nxt.startswith("/"):
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
]
KEY_CHOICES = ["rsa2048", "rsa3072", "rsa4096"]
_ALLOWED_CA = {v for v, _ in CA_CHOICES}
_ALLOWED_KEY = set(KEY_CHOICES)
_ID_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

_IN_PROGRESS: set[str] = set()
_PROGRESS_LOCK = threading.Lock()


def _now() -> str:
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")


def _is_renewing(server_id: str) -> bool:
    with _PROGRESS_LOCK:
        return server_id in _IN_PROGRESS


def _cert_info(server) -> dict:
    cert_path = config.cert_dir_for(server) / f"{server.domain}.cer"
    info = {"present": False, "not_after": None, "days_left": None, "serial": None, "issuer": None}
    if not cert_path.exists():
        return info
    try:
        from cryptography import x509  # lazy import
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        na = cert.not_valid_after_utc
        info.update(
            present=True,
            not_after=na.strftime("%Y-%m-%d"),
            days_left=(na - datetime.datetime.now(datetime.timezone.utc)).days,
            serial=format(cert.serial_number, "X"),
            issuer=cert.issuer.rfc4514_string(),
        )
    except Exception as exc:  # noqa: BLE001
        log.warning("cert parse failed for %s: %s", server.id, exc)
    return info


def _summarize(record: dict | None) -> dict | None:
    if not record:
        return None
    steps = record.get("steps", []) or []
    outcome = record.get("outcome")
    rolled_back = any((s.get("detail") or {}).get("rolled_back") for s in steps)
    if outcome == "failed":
        bad = next((s for s in steps if not s.get("ok", True)), None)
        message = (bad or {}).get("message", "")
    elif steps:
        message = steps[-1].get("message", "")
    else:
        message = ""
    return {
        "server_id": record.get("server_id"), "outcome": outcome,
        "timestamp": record.get("timestamp"), "steps": steps, "message": message,
        "rolled_back": rolled_back, "not_after": record.get("not_after"),
        "serial": record.get("serial"),
    }


def _rows() -> list[dict]:
    rows = []
    for s in config.load_servers():
        rows.append({
            "id": s.id, "name": s.name, "domain": s.domain,
            "host": s.orchestrator_host, "ca": s.acme_ca,
            "cert": _cert_info(s), "last": _summarize(store.latest_for(s.id)),
            "renewing": _is_renewing(s.id),
        })
    return rows


# ============================= dashboard =====================================
@app.route("/")
def index():
    rows = _rows()
    renewing_names = [r["name"] for r in rows if r["renewing"]]
    history = [_summarize(r) for r in store.all_records()[:25]]
    return render_template("index.html", rows=rows, history=history,
                           renewing_names=renewing_names, now=_now())


@app.route("/api/servers")
def api_servers():
    return jsonify(_rows())


@app.route("/api/history")
def api_history():
    return jsonify([_summarize(r) for r in store.all_records()])


@app.route("/renew/<server_id>", methods=["POST"])
def renew(server_id: str):
    with _PROGRESS_LOCK:
        _IN_PROGRESS.add(server_id)

    def _run():
        from .. import renew as renew_mod
        try:
            server = config.get_server(server_id)
            renew_mod.renew_server(server, force=True)
        except Exception as exc:  # noqa: BLE001
            log.error("force renew failed for %s: %s", server_id, exc)
        finally:
            with _PROGRESS_LOCK:
                _IN_PROGRESS.discard(server_id)

    threading.Thread(target=_run, daemon=True).start()
    return redirect(url_for("index"))


@app.route("/deploy/<server_id>", methods=["POST"])
def force_deploy(server_id: str):
    """Re-push the on-disk cert (deploy -> restart), skipping issuance. No CA contact."""
    with _PROGRESS_LOCK:
        _IN_PROGRESS.add(server_id)

    def _run():
        from .. import renew as renew_mod
        try:
            server = config.get_server(server_id)
            renew_mod.redeploy_server(server)
        except Exception as exc:  # noqa: BLE001
            log.error("force deploy failed for %s: %s", server_id, exc)
        finally:
            with _PROGRESS_LOCK:
                _IN_PROGRESS.discard(server_id)

    threading.Thread(target=_run, daemon=True).start()
    return redirect(url_for("index"))


# ============================= settings ======================================
def _flat_from_server(s) -> dict:
    # Secret fields are intentionally blank here — a stored secret is NEVER
    # echoed back to the browser. The template shows a "stored" hint instead.
    return {
        "id": s.id, "name": s.name, "orchestrator_host": s.orchestrator_host,
        "domain": s.domain, "verify_ssl": s.verify_ssl, "acme_ca": s.acme_ca,
        "acme_email": s.acme_email, "key_type": s.key_type, "dns_provider": s.dns_provider,
        "dns_api_token": "", "ssh_user": s.ssh_user, "ssh_key_path": s.ssh_key_path,
        "ssh_known_hosts": s.ssh_known_hosts, "ssh_port": s.ssh_port,
        "restart_command": s.restart_command, "nginx_reload_command": s.nginx_reload_command,
        "api_key_env": s.api_key_env, "api_key": "",
    }


def _flat_blank() -> dict:
    return {
        "id": "", "name": "", "orchestrator_host": "", "domain": "", "verify_ssl": False,
        "acme_ca": "letsencrypt", "acme_email": "", "key_type": "rsa2048",
        "dns_provider": "cloudflare", "dns_api_token": "", "ssh_user": "", "ssh_key_path": "",
        "ssh_known_hosts": str(config.DATA_DIR / "ssh" / "known_hosts"), "ssh_port": 22,
        "restart_command": "sudo systemctl restart --no-block gms.service",
        "nginx_reload_command": "sudo systemctl reload nginx",
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
        "acme_ca": f.get("acme_ca", "letsencrypt").strip(),
        "acme_email": f.get("acme_email", "").strip(),
        "key_type": f.get("key_type", "rsa2048").strip(),
        "dns_provider": f.get("dns_provider", "cloudflare").strip() or "cloudflare",
        "dns_api_token": f.get("dns_api_token", "").strip(),
        "ssh_user": f.get("ssh_user", "").strip(),
        "ssh_key_path": f.get("ssh_key_path", "").strip(),
        "ssh_known_hosts": f.get("ssh_known_hosts", "").strip(),
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
        "verify_ssl": flat["verify_ssl"],
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
    if flat["key_type"] not in _ALLOWED_KEY:
        errors.append("Invalid key type.")
    try:
        port = int(flat["ssh_port"])
        if not (1 <= port <= 65535):
            errors.append("SSH port must be between 1 and 65535.")
    except (TypeError, ValueError):
        errors.append("SSH port must be a number.")
    return errors


def _render_form(flat, errors, is_new, existing=None, status=200):
    return render_template(
        "server_form.html", form=flat, errors=errors, is_new=is_new,
        ca_choices=CA_CHOICES, key_choices=KEY_CHOICES,
        cf_token_set=bool(existing and existing.dns_api_token),
        api_key_set=bool(existing and existing.api_key),
        now=_now(),
    ), status


@app.route("/settings")
def settings():
    return render_template("settings.html", servers=config.load_servers(),
                           ca_labels=dict(CA_CHOICES), now=_now())


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
    log.info("server %s saved via web UI", server.id)
    return redirect(url_for("settings"))


@app.route("/settings/delete/<server_id>", methods=["POST"])
def settings_delete(server_id: str):
    if config.delete_server(server_id):
        log.info("server %s deleted via web UI", server_id)
    return redirect(url_for("settings"))


def main() -> None:
    logging.basicConfig(level="INFO", format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
    app.run(host="0.0.0.0", port=8080)


if __name__ == "__main__":
    main()
