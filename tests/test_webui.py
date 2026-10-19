from __future__ import annotations

from app import config
from app.webui import auth, server as web
from tests.conftest import make_server


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
    monkeypatch.setattr(web, "_served_info", lambda s: {"present": False, "error": "not checked"})
    auth.create_admin("admin", "password123")
    web.app.config["TESTING"] = True
    c = web.app.test_client()
    r = c.post("/login", data={"username": "admin", "password": "password123"})
    assert r.status_code == 302
    return c


def test_dashboard_shows_config_path_and_ssh_problems(layout, known_hosts, monkeypatch):
    config.upsert_server(make_server(ssh_key_path="", ssh_known_hosts=str(known_hosts)))
    c = _client(layout, monkeypatch)
    html = c.get("/").get_data(as_text=True)
    assert str(config.SERVERS_FILE) in html
    assert "SSH activation will fail" in html
    assert "key_path is empty" in html
    assert "API TLS verification is" in html


def test_settings_save_rejects_empty_key_path(layout, known_hosts, monkeypatch):
    c = _client(layout, monkeypatch)
    r = c.post("/settings/save", data={
        "id": "new1", "orchestrator_host": "orch.example.test", "acme_email": "a@b.c",
        "acme_ca": "letsencrypt_test", "key_type": "rsa2048", "ssh_user": "admin",
        "ssh_key_path": "", "ssh_known_hosts": str(known_hosts), "ssh_port": "22",
    })
    assert r.status_code == 400
    assert "key_path is empty" in r.get_data(as_text=True)
    assert not config.server_exists("new1")


def test_settings_save_persists_to_config_dir(layout, rsa_key, known_hosts, monkeypatch):
    c = _client(layout, monkeypatch)
    r = c.post("/settings/save", data={
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
    assert "findings" in j


def test_login_next_cannot_be_offsite(layout, monkeypatch):
    monkeypatch.setattr(web, "_served_info", lambda s: {"present": False, "error": "x"})
    auth.create_admin("admin", "password123")
    c = web.app.test_client()
    r = c.post("/login", data={"username": "admin", "password": "password123", "next": "//evil.example"})
    assert r.headers["Location"].endswith("/")
