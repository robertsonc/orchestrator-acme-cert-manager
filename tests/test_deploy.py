from __future__ import annotations

import requests

from app import deploy, renew, issue
from app.models import StepResult
from tests.conftest import make_server


class _Resp:
    def __init__(self, status, text="", headers=None):
        self.status_code = status
        self.text = text
        self.ok = status < 400
        self.headers = headers or {}


def _files(layout):
    d = layout["certs"] / "orch.example.test"
    d.mkdir(parents=True, exist_ok=True)
    cert, key, ca = d / "orch.example.test.cer", d / "orch.example.test.key", d / "ca.cer"
    for f in (cert, key, ca):
        f.write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    return cert, key, ca


def _run(layout, monkeypatch, script):
    """script: list of responses/exceptions consumed by successive requests.post calls."""
    calls = []

    def fake_post(url, json=None, headers=None, verify=None, timeout=None):
        calls.append(url)
        item = script.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    monkeypatch.setattr(deploy.requests, "post", fake_post)
    monkeypatch.setattr(deploy.time, "sleep", lambda s: None)
    monkeypatch.setattr(deploy, "VALIDATION_ATTEMPTS", 3)
    cert, key, ca = _files(layout)
    res = deploy.deploy_paths(make_server(), cert, key, ca)
    return res, calls


def test_validation_502_then_200_succeeds_without_reissue(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [_Resp(502, "<html>Bad Gateway</html>"), _Resp(200, "{}"), _Resp(204)])
    assert res.ok
    assert res.detail["validation_attempts"] == 2
    assert [c.endswith("/validation") for c in calls] == [True, True, False]


def test_validation_502_three_times_fails_and_never_installs(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [_Resp(502), _Resp(503), _Resp(504)])
    assert not res.ok
    assert len(calls) == 3 and all(c.endswith("/validation") for c in calls)
    d = res.detail
    assert d["phase"] == "validation" and d["kind"] == "transient"
    assert d["status"] == 504 and d["attempt"] == 3 and d["attempts"] == 3
    assert "Force deploy" in res.message and "HTTP 504" in res.message
    assert d["endpoint"] == "/httpsCertificate/validation"


def test_validation_400_is_not_retried(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [_Resp(400, '{"error":"key mismatch"}')])
    assert not res.ok and len(calls) == 1
    assert res.detail["kind"] == "rejected"
    assert "key mismatch" in res.detail["response_excerpt"]


def test_validation_transport_error_is_retried(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [requests.ConnectionError("boom"), _Resp(200), _Resp(204)])
    assert res.ok and len(calls) == 3


def test_install_is_never_retried(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [_Resp(200), _Resp(502)])
    assert not res.ok and len(calls) == 2
    assert res.detail["phase"] == "install" and res.detail["attempts"] == 1


def test_install_transport_error_flags_unknown_state(layout, monkeypatch):
    res, calls = _run(layout, monkeypatch, [_Resp(200), requests.ReadTimeout("t/o")])
    assert not res.ok and len(calls) == 2
    assert "may or may not" in res.message


def test_success_detail_has_both_statuses(layout, monkeypatch):
    res, _ = _run(layout, monkeypatch, [_Resp(200, '{"issuer":"R3"}'), _Resp(204)])
    assert res.detail["validation_status"] == 200 and res.detail["install_status"] == 204


def test_missing_api_key_is_reported(layout, monkeypatch):
    monkeypatch.delenv("ORCH_API_KEY", raising=False)
    cert, key, ca = _files(layout)
    res = deploy.deploy_paths(make_server(api_key=""), cert, key, ca)
    assert not res.ok and "API key" in res.message


def test_redact_strips_key_material_and_secrets():
    body = ('{"keyData":"data:application/octet-stream;base64,QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=",'
            '"password":"hunter2","fullText":"-----BEGIN PRIVATE KEY-----\nMIIE...\n-----END PRIVATE KEY-----"}')
    out = deploy.redact(body)
    assert "hunter2" not in out and "MIIE" not in out and "QUJDREVG" not in out
    assert "<redacted>" in out and "<pem-redacted>" in out
    assert len(deploy.redact("x" * 5000)) <= deploy._EXCERPT_LEN + 1


def test_force_deploy_never_contacts_the_ca(layout, monkeypatch):
    def no_ca(*a, **k):
        raise AssertionError("issue_or_renew must not be called by redeploy")
    monkeypatch.setattr(issue, "issue_or_renew", no_ca)
    _files(layout)
    monkeypatch.setattr(renew.deploy, "deploy", lambda s: StepResult("deploy", True, "ok"))
    monkeypatch.setattr(renew.restart, "restart", lambda s: StepResult("restart", True, "ok"))
    monkeypatch.setattr(renew.notify, "send", lambda r: None)
    rec = renew.redeploy_server(make_server())
    assert rec.outcome == "success" and [s["step"] for s in rec.steps] == ["deploy", "restart"]


def test_failed_deploy_is_recorded_as_failed_with_detail(layout, monkeypatch):
    _files(layout)
    bad = StepResult("deploy", False, "Certificate validation failed", detail={"phase": "validation", "status": 502})
    monkeypatch.setattr(renew.deploy, "deploy", lambda s: bad)
    monkeypatch.setattr(renew.restart, "restart", lambda s: StepResult("restart", True, "must not run"))
    monkeypatch.setattr(renew.notify, "send", lambda r: None)
    rec = renew.redeploy_server(make_server())
    assert rec.outcome == "failed"
    assert [s["step"] for s in rec.steps] == ["deploy"]
    assert rec.steps[0]["detail"]["status"] == 502


def test_lego_uses_lab_ca_directory_and_trust(layout, monkeypatch):
    from app import config as cfg
    monkeypatch.setattr(cfg, "LAB_CA_HOST", "ca.lab.example.net")
    monkeypatch.setattr(cfg, "LAB_CA_PORT", 9000)
    monkeypatch.setattr(cfg, "LAB_CA_PROVISIONER", "lab")
    monkeypatch.setattr(cfg, "LAB_CA_ROOT", layout["data"] / "pki" / "certs" / "root_ca.crt")
    s = make_server(acme_ca="lab")
    assert issue._acme_url(s) == "https://ca.lab.example.net:9000/acme/lab/directory"
    env = issue.lego_environment(s, "tok")
    assert env["LEGO_CA_CERTIFICATES"] == str(cfg.LAB_CA_ROOT)
    assert env[cfg.CF_TOKEN_ENV] == "tok"
    assert "LEGO_CA_CERTIFICATES" not in issue.lego_environment(make_server(acme_ca="letsencrypt"), "tok")
    # not configured -> issuance refuses with guidance before running lego
    res = issue.issue_or_renew(s, force=True)
    assert not res.ok and "setup.sh --with-ca" in res.message


def _lab_root(layout, monkeypatch, cfg):
    root = layout["data"] / "pki" / "certs" / "root_ca.crt"
    root.parent.mkdir(parents=True, exist_ok=True)
    root.write_text("-----BEGIN CERTIFICATE-----\nLABROOT\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(cfg, "LAB_CA_HOST", "ca.lab.example.net")
    monkeypatch.setattr(cfg, "LAB_CA_ROOT", root)
    monkeypatch.setattr(cfg, "TRUST_DIR", layout["cfg"] / "trust")
    monkeypatch.setattr(cfg, "COMBINED_TRUST_FILE", layout["cfg"] / "trust" / "api-trust.pem")
    return root


def test_api_trust_bundle_combines_system_lab_and_custom(layout, monkeypatch):
    from app import config as cfg
    import certifi
    monkeypatch.setattr(cfg, "LAB_CA_HOST", "")
    monkeypatch.setattr(cfg, "LAB_CA_ROOT", layout["data"] / "nope")
    assert cfg.api_trust_bundle() is True                      # nothing to add -> plain system trust
    _lab_root(layout, monkeypatch, cfg)
    path = cfg.api_trust_bundle()
    text = open(path).read()
    assert "LABROOT" in text and open(certifi.where()).read()[:40] in text
    custom = layout["data"] / "custom.pem"; custom.write_text("-----BEGIN CERTIFICATE-----\nCUSTOM\n-----END CERTIFICATE-----\n")
    assert "CUSTOM" in open(cfg.api_trust_bundle(str(custom))).read()
    assert cfg.api_trust_bundle(str(custom)) == path          # cached, same file


def test_verified_calls_use_combined_trust_whatever_ca_is_configured(layout, monkeypatch):
    """Migration public->lab, lab->public and rollback all verify against system + lab roots."""
    from app import config as cfg
    root = _lab_root(layout, monkeypatch, cfg)
    seen = []

    def fake_post(url, json=None, headers=None, verify=None, timeout=None):
        seen.append(verify)
        return _Resp(200) if url.endswith("/validation") else _Resp(204)

    monkeypatch.setattr(deploy.requests, "post", fake_post)
    cert, key, ca = _files(layout)
    for ca_choice in ("lab", "letsencrypt", "letsencrypt_test"):
        assert deploy.deploy_paths(make_server(acme_ca=ca_choice, verify_ssl=True), cert, key, ca).ok
    assert len(set(seen)) == 1 and seen[0].endswith("api-trust.pem")
    text = open(seen[0]).read()
    assert "LABROOT" in text and "BEGIN CERTIFICATE" in text
    # rollback uses the same code path
    from app import restart
    monkeypatch.setattr(restart, "_reload_nginx", lambda s: StepResult("restart", True, "ok"))
    monkeypatch.setattr(restart, "_wait_for_served_serial", lambda s, want, t: (True, 0))
    rb = restart._rollback_dir(make_server()); rb.mkdir(parents=True, exist_ok=True)
    for name in ("orch.example.test.cer", "orch.example.test.key", "ca.cer"):
        (rb / name).write_text("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n")
    monkeypatch.setattr(restart, "_deployed_serial_from", lambda p: 1)
    seen.clear()
    restart._attempt_rollback(make_server(acme_ca="lab", verify_ssl=True), failed_serial=2)
    assert seen and seen[0].endswith("api-trust.pem")
    # verify_ssl off still means no verification, root present or not
    seen.clear()
    deploy.deploy_paths(make_server(acme_ca="lab", verify_ssl=False), cert, key, ca)
    assert seen[0] is False
    assert root.is_file()
