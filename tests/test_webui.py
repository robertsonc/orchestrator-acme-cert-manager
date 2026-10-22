from __future__ import annotations

import re

from app import config
from app.webui import auth, server as web
from tests.conftest import make_server


def _csrf(c, path="/login"):
    """Fetch a page to receive the csrf cookie and read the matching form token."""
    html = c.get(path).get_data(as_text=True)
    m = re.search(r'name="_csrf" value="([0-9a-f]+)"', html)
    assert m, f"no csrf token on {path}"
    return m.group(1)


def _post(c, url, data=None, path="/login"):
    data = dict(data or {})
    data.setdefault("_csrf", _csrf(c, path))
    return c.post(url, data=data)


_NO_SERVED = {"present": False, "error": "not checked", "serial": None, "environment": None, "self_signed": None}


def test_environment_detection():
    assert web.environment_of("CN=(STAGING) Ersatz Emmer YR2,O=(STAGING) Let's Encrypt,C=US") == "staging"
    assert web.environment_of("CN=Fake LE Intermediate X1") == "staging"
    assert web.environment_of("CN=YR2,O=Let's Encrypt,C=US") == "production"
    assert web.environment_of(None) is None


def test_lifecycle_states():
    s = make_server(acme_ca="letsencrypt")
    issued = {"present": True, "serial": "AA", "environment": "production"}
    assert web.lifecycle(s, {"present": False}, {})["state"] == "none"
    assert web.lifecycle(s, issued, {"present": False, "error": "timed out"})["state"] == "unknown"
    live = web.lifecycle(s, issued, {"present": True, "serial": "AA", "environment": "production", "error": None})
    assert live["state"] == "live"
    pend = web.lifecycle(s, issued, {"present": True, "serial": "BB", "environment": "staging", "error": None})
    assert pend["state"] == "pending"
    assert "still serving staging certificate" in pend["message"]
    assert "Force deploy" in pend["message"]
    stale = web.lifecycle(s, {"present": True, "serial": "AA", "environment": "staging"},
                          {"present": True, "serial": "AA", "environment": "staging", "error": None})
    assert stale["state"] == "live" and "STAGING" in stale["message"]


def test_form_validation_rejects_bad_ssh(layout, known_hosts):
    flat = web._flat_blank()
    flat.update(id="x", orchestrator_host="orch.example.test", acme_email="a@b.c",
                ssh_user="", ssh_key_path="", ssh_known_hosts=str(known_hosts))
    errs = web._validate(flat, is_new=True)
    assert any("ssh.user is empty" in e for e in errs)
    assert any("key_path is empty" in e for e in errs)


def test_form_validation_accepts_good_ssh(server):
    flat = web._flat_from_server(server)
    flat["id"] = "y"
    assert web._validate(flat, is_new=True) == []


def _client(layout, monkeypatch):
    monkeypatch.setattr(web, "_served_info", lambda *a: dict(_NO_SERVED))
    auth.create_admin("admin", "password123")
    web.app.config["TESTING"] = True
    c = web.app.test_client()
    r = _post(c, "/login", {"username": "admin", "password": "password123"})
    assert r.status_code == 302
    return c


def test_dashboard_shows_config_path_and_ssh_problems(layout, known_hosts, monkeypatch):
    config.upsert_server(make_server(ssh_key_path="", ssh_known_hosts=str(known_hosts)))
    c = _client(layout, monkeypatch)
    html = c.get("/").get_data(as_text=True)
    assert str(config.SERVERS_FILE) in html
    assert "SSH configuration invalid" in html          # health reason on the fleet row
    assert "attention" in html
    detail = c.get("/server/orch-test").get_data(as_text=True)
    assert "Activation will fail" in detail
    assert "key_path is empty" in detail
    assert "unverified" in detail                       # API TLS verification is off
    frag = c.get("/partials/fleet").get_data(as_text=True)
    assert frag.lstrip().startswith("<div data-busy=")
    assert c.get("/server/does-not-exist").status_code == 404


def test_settings_save_rejects_empty_key_path(layout, known_hosts, monkeypatch):
    c = _client(layout, monkeypatch)
    r = _post(c, "/settings/save", {
        "id": "new1", "orchestrator_host": "orch.example.test", "acme_email": "a@b.c",
        "acme_ca": "letsencrypt_test", "key_type": "rsa2048", "ssh_user": "admin",
        "ssh_key_path": "", "ssh_known_hosts": str(known_hosts), "ssh_port": "22",
    })
    assert r.status_code == 400
    assert "key_path is empty" in r.get_data(as_text=True)
    assert not config.server_exists("new1")


def test_settings_save_persists_to_config_dir(layout, rsa_key, known_hosts, monkeypatch):
    c = _client(layout, monkeypatch)
    r = _post(c, "/settings/save", {
        "id": "new2", "orchestrator_host": "orch.example.test", "acme_email": "a@b.c",
        "acme_ca": "letsencrypt_test", "key_type": "rsa2048", "ssh_user": "admin",
        "ssh_key_path": str(rsa_key[0]), "ssh_known_hosts": str(known_hosts), "ssh_port": "22",
        "restart_command": "sudo /bin/systemctl restart --no-block gms.service",
        "nginx_reload_command": "sudo /bin/systemctl reload nginx",
    })
    assert r.status_code == 302
    assert config.SERVERS_FILE.exists() and config.server_exists("new2")


def test_api_status_reports_paths(layout, monkeypatch):
    c = _client(layout, monkeypatch)
    j = c.get("/api/status").get_json()
    assert j["servers_file"] == str(config.SERVERS_FILE)
    assert "findings" in j and "lab_ca" in j
    assert c.get("/settings").status_code == 200
    assert c.get("/settings/new").status_code == 200


def test_login_next_cannot_be_offsite(layout, monkeypatch):
    monkeypatch.setattr(web, "_served_info", lambda *a: dict(_NO_SERVED))
    auth.create_admin("admin", "password123")
    c = web.app.test_client()
    r = _post(c, "/login", {"username": "admin", "password": "password123", "next": "//evil.example"})
    assert r.headers["Location"].endswith("/")


def _row(**over):
    base = {"renewing": False, "ssh_problems": [], "cert": {"present": True, "days_left": 60, "environment": "production"},
            "lifecycle": {"state": "live", "configured_env": "production", "message": ""}, "last": {"outcome": "success"}}
    base.update(over)
    return base


def test_health_rollup_order():
    assert web.health(_row())["state"] == "ok"
    assert web.health(_row(renewing=True))["state"] == "working"
    assert web.health(_row(ssh_problems=["x"]))["state"] == "critical"
    assert web.health(_row(last={"outcome": "failed"}))["state"] == "critical"
    assert web.health(_row(cert={"present": True, "days_left": -1, "environment": "production"}))["state"] == "critical"
    w = web.health(_row(lifecycle={"state": "pending", "configured_env": "production", "message": ""}))
    assert w["state"] == "warning" and "not yet served" in w["reasons"][0]
    assert web.health(_row(cert={"present": True, "days_left": 12, "environment": "production"}))["state"] == "warning"
    assert web.health(_row(cert={"present": False}, lifecycle={"state": "none", "configured_env": "production", "message": ""}, last=None))["state"] == "none"
    assert web.health(_row(lifecycle={"state": "unknown", "configured_env": "production", "message": "m"}))["state"] == "unknown"


def test_fleet_summary_counts():
    rows = [
        {"health": {"state": "ok"}, "cert": {"present": True, "days_left": 60}, "renewing": False},
        {"health": {"state": "warning"}, "cert": {"present": True, "days_left": 12}, "renewing": False},
        {"health": {"state": "critical"}, "cert": {"present": False}, "renewing": False},
        {"health": {"state": "working"}, "cert": {"present": True, "days_left": 40}, "renewing": True},
    ]
    s = web.fleet_summary(rows)
    assert (s["servers"], s["healthy"], s["attention"], s["expiring"], s["working"], s["min_days"]) == (4, 1, 2, 1, 1, 12)


def test_relative_time():
    import datetime as dt
    now = dt.datetime.now(dt.timezone.utc)
    assert web.relative_time((now - dt.timedelta(hours=3)).isoformat()) == "3h ago"
    assert web.relative_time((now - dt.timedelta(days=2)).isoformat()) == "2d ago"
    assert web.relative_time(None) == "—"


def test_server_partial_and_api(layout, server, monkeypatch):
    config.upsert_server(server)
    c = _client(layout, monkeypatch)
    frag = c.get("/partials/server/orch-test").get_data(as_text=True)
    assert frag.lstrip().startswith("<div data-busy=") and "Activation (SSH)" in frag
    j = c.get("/api/server/orch-test").get_json()
    assert j["server"]["health"]["state"] in ("none", "unknown")
    assert "history" in j


def test_environment_of_lab_and_form_choice(layout, monkeypatch):
    from tests.test_config_persistence import _lab_pki
    root, inter = _lab_pki(layout, monkeypatch)
    assert web.environment_of(inter.subject.rfc4514_string()) == "lab"
    assert web.environment_of("CN=YR2,O=Let's Encrypt,C=US") == "production"
    s = make_server(acme_ca="lab")
    issued = {"present": True, "serial": "AA", "environment": "lab"}
    live = web.lifecycle(s, issued, {"present": True, "serial": "AA", "environment": "lab", "error": None})
    assert live["state"] == "live" and live["configured_env"] == "lab" and "run Force renew" not in live["message"]
    mismatch = web.lifecycle(make_server(acme_ca="letsencrypt"), issued,
                             {"present": True, "serial": "AA", "environment": "lab", "error": None})
    assert "issued by the LAB CA" in mismatch["message"]
    flat = web._flat_blank(); flat.update(id="l1", orchestrator_host="orch.lab.example.net", acme_email="a@b.c", acme_ca="lab")
    assert not any("lab CA is not configured" in e for e in web._validate(flat, is_new=True))
    monkeypatch.setattr(config, "LAB_CA_HOST", "")
    assert any("lab CA is not configured" in e for e in web._validate(flat, is_new=True))
