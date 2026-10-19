from __future__ import annotations

import os

import paramiko
import pytest

from app import restart, sshcheck
from app.models import StepResult
from tests.conftest import make_server


def test_empty_key_path_is_actionable(layout, known_hosts):
    probs = sshcheck.validate(make_server(ssh_key_path="", ssh_known_hosts=str(known_hosts)))
    assert any("key_path is empty" in p and "orch_restart" in p for p in probs)


def test_missing_key_file(layout, known_hosts):
    probs = sshcheck.validate(make_server(ssh_key_path=str(layout["ssh"] / "nope"),
                                          ssh_known_hosts=str(known_hosts)))
    assert any("not found at" in p for p in probs)


@pytest.mark.skipif(os.geteuid() == 0, reason="root ignores file modes")
def test_unreadable_key_file(layout, rsa_key, known_hosts):
    p, _ = rsa_key
    os.chmod(p, 0o000)
    try:
        probs = sshcheck.validate(make_server(ssh_key_path=str(p), ssh_known_hosts=str(known_hosts)))
    finally:
        os.chmod(p, 0o600)
    assert any("not readable" in p for p in probs)


def test_invalid_key_file(layout, known_hosts):
    p = layout["ssh"] / "junk"
    p.write_text("this is not a key\n")
    probs = sshcheck.validate(make_server(ssh_key_path=str(p), ssh_known_hosts=str(known_hosts)))
    assert any("could not be parsed" in x for x in probs)


def test_public_key_given_instead_of_private(layout, rsa_key, known_hosts):
    _, k = rsa_key
    p = layout["ssh"] / "orch_restart.pub"
    p.write_text(f"{k.get_name()} {k.get_base64()} test\n")
    probs = sshcheck.validate(make_server(ssh_key_path=str(p), ssh_known_hosts=str(known_hosts)))
    assert any("could not be parsed" in x for x in probs)


def test_passphrase_protected_key(layout, known_hosts):
    k = paramiko.RSAKey.generate(2048)
    p = layout["ssh"] / "enc"
    k.write_private_key_file(str(p), password="secret")
    probs = sshcheck.validate(make_server(ssh_key_path=str(p), ssh_known_hosts=str(known_hosts)))
    assert any("passphrase-protected" in x for x in probs)


def test_ed25519_and_ecdsa_keys_parse(layout, known_hosts):
    for cls, name in ((paramiko.Ed25519Key, "ed"), (paramiko.ECDSAKey, "ec")):
        p = layout["ssh"] / name
        if cls is paramiko.ECDSAKey:
            cls.generate().write_private_key_file(str(p))
        else:
            # paramiko cannot generate Ed25519; synthesize via cryptography
            from cryptography.hazmat.primitives import serialization
            from cryptography.hazmat.primitives.asymmetric import ed25519
            pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.OpenSSH,
                serialization.NoEncryption())
            p.write_bytes(pem)
        assert sshcheck.load_private_key(str(p)) is not None


def test_missing_user_and_known_hosts(layout, rsa_key):
    probs = sshcheck.validate(make_server(ssh_user="", ssh_key_path=str(rsa_key[0]), ssh_known_hosts=""))
    assert any("ssh.user is empty" in p for p in probs)
    assert any("known_hosts is empty" in p for p in probs)


def test_known_hosts_without_entry_for_host(layout, rsa_key, known_hosts):
    s = make_server(ssh_key_path=str(rsa_key[0]), ssh_known_hosts=str(known_hosts),
                    orchestrator_host="other.example.test")
    probs = sshcheck.validate(s)
    assert any("no entry for 'other.example.test'" in p for p in probs)


def test_known_hosts_entry_name_uses_port_syntax(layout, rsa_key, known_hosts):
    assert sshcheck.known_hosts_entry_name("h", 22) == "h"
    assert sshcheck.known_hosts_entry_name("h", 2222) == "[h]:2222"
    s = make_server(ssh_key_path=str(rsa_key[0]), ssh_known_hosts=str(known_hosts), ssh_port=2222)
    assert any("[orch.example.test]:2222" in p for p in sshcheck.validate(s))


def test_valid_configuration_has_no_problems(server):
    assert sshcheck.validate(server) == []


def test_authorization_probe():
    assert sshcheck.authorization_probe("sudo /bin/systemctl reload nginx") == \
        "sudo -n -l /bin/systemctl reload nginx"
    assert sshcheck.authorization_probe("sudo -n /bin/systemctl restart --no-block gms.service") == \
        "sudo -n -l /bin/systemctl restart --no-block gms.service"
    assert sshcheck.authorization_probe("/usr/sbin/service gms restart") is None
    assert sshcheck.authorization_probe("") is None


class _FakeClient:
    """Minimal stand-in for paramiko.SSHClient.exec_command used by sshcheck.run."""

    def __init__(self, responses):
        self.responses = responses
        self.commands = []
        self.closed = False

    def exec_command(self, cmd, timeout=None):
        self.commands.append(cmd)
        rc, out, err = self.responses.pop(0)

        class _Ch:
            def recv_exit_status(self_inner):
                return rc

        class _F:
            def __init__(self, data):
                self._d = data
                self.channel = _Ch()

            def read(self):
                return self._d.encode()

        return None, _F(out), _F(err)

    def close(self):
        self.closed = True


def test_test_connection_reports_config_problems_without_connecting(layout, known_hosts, monkeypatch):
    called = []
    monkeypatch.setattr(paramiko.SSHClient, "connect", lambda *a, **k: called.append(1))
    res = sshcheck.test_connection(make_server(ssh_key_path="", ssh_known_hosts=str(known_hosts)))
    assert not res.ok and "key_path is empty" in res.message
    assert called == []


def test_test_connection_sudo_password_required(server, monkeypatch):
    fake = _FakeClient([(1, "", "sudo: a password is required"), (0, "/bin/systemctl reload nginx", "")])
    monkeypatch.setattr(sshcheck, "open_client", lambda s: fake)
    res = sshcheck.test_connection(server)
    assert not res.ok
    assert "NOPASSWD" in res.message
    assert fake.commands[0].startswith("sudo -n -l ")
    assert fake.closed


def test_test_connection_success(server, monkeypatch):
    fake = _FakeClient([(0, "/bin/systemctl restart --no-block gms.service", ""),
                        (0, "/bin/systemctl reload nginx", "")])
    monkeypatch.setattr(sshcheck, "open_client", lambda s: fake)
    res = sshcheck.test_connection(server)
    assert res.ok and "without a password" in res.message
    assert len(res.detail["checks"]) == 2


def test_connect_error_classification(server):
    bad = paramiko.AuthenticationException("Authentication failed.")
    assert "authorized_keys" in sshcheck._classify_connect_error(bad, server)
    hk = paramiko.SSHException("Server 'x' not found in known_hosts")
    assert "not pinned" in sshcheck._classify_connect_error(hk, server)
    assert "timed out" in sshcheck._classify_connect_error(__import__("socket").timeout(), server)


def test_restart_preflight_blocks_before_any_network(layout, known_hosts, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("must not be reached")
    monkeypatch.setattr(restart, "_deployed_serial", boom)
    res = restart.restart(make_server(ssh_key_path="", ssh_known_hosts=str(known_hosts)))
    assert isinstance(res, StepResult) and not res.ok
    assert res.detail["phase"] == "preflight"
    assert "key_path is empty" in res.message
