"""setup.sh --with-ca re-run behaviour, exercised with a fake `docker` on PATH.

The shim answers `docker info` and turns the `docker run ... /pki-init/lab-ca-init.sh`
invocation into a native run of the init script with the same mounts and
environment, so the setup.sh metadata/drift logic is tested end to end without a
daemon. Needs the `step` CLI like the other native tests.
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
STEP = shutil.which("step")
pytestmark = pytest.mark.skipif(STEP is None, reason="step CLI not on PATH")

SHIM = r"""#!/bin/bash
# fake docker: `info` succeeds; `run` executes the lab CA init script natively.
if [[ "$1" == "info" ]]; then exit 0; fi
if [[ "$1" != "run" ]]; then exit 0; fi
shift
envs=(); vols=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -e) envs+=("$2"); shift 2 ;;
    -v) vols+=("$2"); shift 2 ;;
    -u|--entrypoint) shift 2 ;;
    *) shift ;;
  esac
done
for v in "${vols[@]}"; do
  src="${v%%:*}"; rest="${v#*:}"; dst="${rest%%:*}"
  case "$dst" in /home/step) steppath="$src" ;; /root-offline) offline="$src" ;; /pki-init) tpl="$src" ;; esac
done
for e in "${envs[@]}"; do case "$e" in STEPPATH=*|HOME=*|OFFLINE=*) ;; *) export "$e" ;; esac; done
STEPPATH="$steppath" OFFLINE="$offline" LAB_CA_TEMPLATE_DIR="$tpl" bash "$tpl/lab-ca-init.sh"
"""


def _setup(tmp: Path, *args: str) -> subprocess.CompletedProcess:
    work = tmp / "repo"
    if not work.exists():
        work.mkdir()
        for name in ("setup.sh", ".env.example"):
            shutil.copy(REPO / name, work / name)
        shutil.copytree(REPO / "pki", work / "pki")
        shutil.copytree(REPO / "config", work / "config")
        (work / "config" / "servers.json").unlink(missing_ok=True)
        shim_dir = tmp / "bin"; shim_dir.mkdir(exist_ok=True)
        (shim_dir / "docker").write_text(SHIM); (shim_dir / "docker").chmod(0o755)
    env = dict(os.environ, PATH=f"{tmp / 'bin'}:{os.environ['PATH']}")
    for k in ("LAB_CA_DOMAIN", "LAB_CA_HOST", "LAB_CA_NAME", "LAB_CA_PORT"):
        env.pop(k, None)
    base = ["bash", str(work / "setup.sh"), "--non-interactive", "--skip-docker", "--skip-remote",
            "--host", "orch.lab.example.net", "--email", "ops@example.test", "--with-ca"]
    return subprocess.run(base + list(args), env=env, capture_output=True, text=True, timeout=180, cwd=work)


def _env(tmp: Path) -> dict[str, str]:
    out = {}
    for line in (tmp / "repo" / ".env").read_text().splitlines():
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1); out[k] = v
    return out


def test_rerun_without_port_keeps_the_initialised_port(tmp_path):
    first = _setup(tmp_path, "--lab-domain", "lab.example.net", "--ca-port", "9443")
    assert first.returncode == 0, first.stdout + first.stderr
    assert _env(tmp_path)["LAB_CA_PORT"] == "9443" and _env(tmp_path)["LAB_CA_HOST"] == "ca.lab.example.net"
    assert (tmp_path / "repo" / "data" / "pki-root" / "root_ca_key").is_file()
    assert not (tmp_path / "repo" / "data" / "pki" / "secrets" / "root_ca_key").exists()
    again = _setup(tmp_path)                       # no --lab-domain, no --ca-port
    assert again.returncode == 0, again.stdout + again.stderr
    assert "nothing to do" in again.stdout
    assert _env(tmp_path)["LAB_CA_PORT"] == "9443"  # not reset to 9000


def test_rerun_with_different_identity_is_refused(tmp_path):
    assert _setup(tmp_path, "--lab-domain", "lab.example.net").returncode == 0
    bad = _setup(tmp_path, "--lab-domain", "other.example.net")
    assert bad.returncode != 0 and "differs from the initialised CA" in bad.stdout + bad.stderr
    assert _env(tmp_path)["LAB_CA_DOMAIN"] == "lab.example.net"   # .env untouched
    port = _setup(tmp_path, "--ca-port", "9999")
    assert port.returncode != 0 and "--ca-port" in port.stdout + port.stderr
