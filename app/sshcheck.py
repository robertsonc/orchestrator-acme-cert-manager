"""SSH configuration validation and a non-disruptive connection test.

Everything the activation stage needs from SSH is checked here *before* a
Paramiko connection is attempted, so a misconfiguration surfaces as a short,
actionable message instead of a low-level traceback such as
"[Errno 2] No such file or directory: ''".

validate(server)      -> list of human-readable problems (empty == OK)
load_private_key(p)   -> paramiko PKey, or raises SSHConfigError
test_connection(s)    -> StepResult: authenticates and checks sudo
                         authorization with `sudo -n -l` (never restarts anything)
"""
from __future__ import annotations

import logging
import os
import shlex
import socket
from pathlib import Path

import paramiko

from . import config
from .models import ServerConfig, StepResult

log = logging.getLogger("sshcheck")

STEP = "ssh-test"
_CONNECT_TIMEOUT = 20
_CMD_TIMEOUT = 30
_KEY_CLASSES = (paramiko.RSAKey, paramiko.Ed25519Key, paramiko.ECDSAKey)


class SSHConfigError(Exception):
    """A problem with the SSH settings that must be fixed by the operator."""


# --------------------------------------------------------------------------- static checks

def known_hosts_entry_name(host: str, port: int) -> str:
    """The known_hosts key name Paramiko/OpenSSH use for host:port."""
    return host if int(port) == 22 else f"[{host}]:{port}"


def load_private_key(path: str) -> paramiko.PKey:
    """Parse an unencrypted private key file of any type Paramiko supports."""
    if not path:
        raise SSHConfigError("ssh.key_path is empty")
    p = Path(path)
    if not p.is_file():
        raise SSHConfigError(f"private key not found at {path}")
    if not os.access(p, os.R_OK):
        raise SSHConfigError(f"private key at {path} is not readable by the service user "
                             f"(uid {os.getuid()}) — fix the file's ownership/permissions")
    last: Exception | None = None
    for cls in _KEY_CLASSES:
        try:
            return cls.from_private_key_file(str(p))
        except paramiko.PasswordRequiredException as exc:
            raise SSHConfigError(
                f"private key at {path} is passphrase-protected; the unattended service "
                f"needs a key without a passphrase") from exc
        except (paramiko.SSHException, ValueError, OSError) as exc:
            last = exc
    raise SSHConfigError(
        f"private key at {path} could not be parsed as RSA, Ed25519 or ECDSA "
        f"(is it a *private* key in OpenSSH/PEM format?): {last}")


def validate(server: ServerConfig) -> list[str]:
    """Return every SSH configuration problem for this server (empty list == OK)."""
    problems: list[str] = []

    if not server.ssh_user:
        problems.append("ssh.user is empty — set the Orchestrator login the activation commands run as.")

    if not server.ssh_key_path:
        problems.append(f"ssh.key_path is empty — configure a private key path, for example "
                        f"{config.DEFAULT_SSH_KEY}.")
    else:
        try:
            load_private_key(server.ssh_key_path)
        except SSHConfigError as exc:
            problems.append(str(exc))

    if not (1 <= int(server.ssh_port) <= 65535):
        problems.append(f"ssh.port {server.ssh_port} is out of range.")

    if not server.ssh_known_hosts:
        problems.append(f"ssh.known_hosts is empty — pin the Orchestrator host key, for example "
                        f"{config.DEFAULT_KNOWN_HOSTS}.")
    else:
        kh = Path(server.ssh_known_hosts)
        if not kh.is_file():
            problems.append(f"known_hosts not found at {server.ssh_known_hosts} — run setup.sh "
                            f"(or ssh-keyscan) and verify the fingerprint before trusting it.")
        elif not os.access(kh, os.R_OK):
            problems.append(f"known_hosts at {server.ssh_known_hosts} is not readable by the service user.")
        else:
            try:
                hk = paramiko.HostKeys(str(kh))
            except (paramiko.SSHException, OSError, ValueError) as exc:
                problems.append(f"known_hosts at {server.ssh_known_hosts} could not be parsed: {exc}")
            else:
                name = known_hosts_entry_name(server.orchestrator_host, server.ssh_port)
                if not hk.lookup(name):
                    problems.append(
                        f"known_hosts at {server.ssh_known_hosts} has no entry for {name!r} — "
                        f"the entry must match the host (and port) the tool connects to.")

    if not server.restart_command and not server.nginx_reload_command:
        problems.append("no restart or nginx reload command is configured; nothing would activate the certificate.")

    return problems


# --------------------------------------------------------------------------- connection

def _classify_connect_error(exc: Exception, server: ServerConfig) -> str:
    name = known_hosts_entry_name(server.orchestrator_host, server.ssh_port)
    if isinstance(exc, paramiko.BadHostKeyException):
        return (f"SSH host key for {name} does not match the pinned entry in "
                f"{server.ssh_known_hosts}. If the appliance was rebuilt, re-pin it after "
                f"verifying the new fingerprint out of band; never disable host-key checking.")
    if isinstance(exc, paramiko.AuthenticationException):
        return (f"SSH authentication failed for {server.ssh_user}@{name}: the public half of "
                f"{server.ssh_key_path} is not in that account's authorized_keys, or the account "
                f"does not permit key authentication.")
    if isinstance(exc, paramiko.SSHException):
        msg = str(exc)
        if "not found in known_hosts" in msg or "Unknown server" in msg:
            return (f"SSH host key for {name} is not pinned in {server.ssh_known_hosts}; "
                    f"add it after verifying the fingerprint.")
        return f"SSH negotiation with {name} failed: {msg}"
    if isinstance(exc, socket.timeout):
        return f"SSH connection to {name} timed out after {_CONNECT_TIMEOUT}s."
    if isinstance(exc, OSError):
        return f"SSH connection to {name} failed: {exc}"
    return f"SSH connection to {name} failed: {exc!r}"


def open_client(server: ServerConfig) -> paramiko.SSHClient:
    """Validate the SSH settings and return a connected client.

    Raises SSHConfigError with an operator-facing message on any failure.
    """
    problems = validate(server)
    if problems:
        raise SSHConfigError(
            f"SSH configuration invalid for {server.id}:\n  - " + "\n  - ".join(problems))

    pkey = load_private_key(server.ssh_key_path)
    client = paramiko.SSHClient()
    try:
        client.load_host_keys(server.ssh_known_hosts)
    except (OSError, paramiko.SSHException) as exc:
        raise SSHConfigError(f"cannot load known_hosts {server.ssh_known_hosts}: {exc}") from exc
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    try:
        client.connect(
            hostname=server.orchestrator_host,
            port=int(server.ssh_port),
            username=server.ssh_user,
            pkey=pkey,
            timeout=_CONNECT_TIMEOUT,
            banner_timeout=_CONNECT_TIMEOUT,
            auth_timeout=_CONNECT_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
    except (paramiko.SSHException, OSError) as exc:
        client.close()
        raise SSHConfigError(_classify_connect_error(exc, server)) from exc
    return client


def run(client: paramiko.SSHClient, cmd: str, timeout: int = _CMD_TIMEOUT) -> tuple[int, str, str]:
    """Run one command; returns (exit_status, stdout, stderr)."""
    _, stdout, stderr = client.exec_command(cmd, timeout=timeout)
    rc = stdout.channel.recv_exit_status()
    return (rc,
            stdout.read().decode(errors="replace").strip(),
            stderr.read().decode(errors="replace").strip())


def authorization_probe(command: str) -> str | None:
    """Turn 'sudo <cmd>' into 'sudo -n -l <cmd>' (checks sudoers, runs nothing).

    Returns None when the command does not go through sudo (nothing to probe).
    """
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts or parts[0] != "sudo":
        return None
    rest = [p for p in parts[1:] if p not in ("-n", "--non-interactive")]
    if not rest:
        return None
    return "sudo -n -l " + " ".join(shlex.quote(p) for p in rest)


def test_connection(server: ServerConfig) -> StepResult:
    """Authenticate and verify sudo authorization for the activation commands.

    Runs `sudo -n -l <command>` for each configured command, which asks sudo
    whether the command would be permitted without a password. No service is
    restarted or reloaded.
    """
    try:
        client = open_client(server)
    except SSHConfigError as exc:
        return StepResult(STEP, ok=False, message=str(exc), detail={"phase": "connect"})

    checks: list[dict] = []
    ok = True
    try:
        for label, cmd in (("restart_command", server.restart_command),
                           ("nginx_reload_command", server.nginx_reload_command)):
            if not cmd:
                continue
            probe = authorization_probe(cmd)
            if probe is None:
                checks.append({"command": cmd, "ok": True, "note": "not using sudo; authorization not probed"})
                continue
            try:
                rc, out, err = run(client, probe)
            except (paramiko.SSHException, socket.timeout, OSError) as exc:
                ok = False
                checks.append({"command": cmd, "ok": False, "error": f"probe failed: {exc}"})
                continue
            passed = rc == 0
            ok = ok and passed
            entry = {"command": cmd, "ok": passed, "probe": probe, "exit": rc,
                     "stdout": out[:500], "stderr": err[:500]}
            if not passed:
                if "password" in (err + out).lower():
                    entry["hint"] = (f"sudo wants a password for {server.ssh_user}: add a NOPASSWD "
                                     f"sudoers rule scoped to exactly this command.")
                else:
                    entry["hint"] = "sudoers does not permit this exact command for this user."
            checks.append(entry)
    finally:
        client.close()

    if ok:
        msg = (f"SSH key authentication to {server.ssh_user}@{server.orchestrator_host} succeeded "
               f"and sudo permits the activation commands without a password.")
    else:
        bad = [c for c in checks if not c.get("ok")]
        msg = (f"SSH authentication to {server.ssh_user}@{server.orchestrator_host} succeeded, "
               f"but sudo authorization failed for: "
               + "; ".join(f"{c['command']!r} ({c.get('hint') or c.get('error')})" for c in bad))
    return StepResult(STEP, ok=ok, message=msg, detail={"phase": "authorize", "checks": checks})
