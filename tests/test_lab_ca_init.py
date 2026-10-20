"""Exercise pki/lab-ca-init.sh natively when a `step` binary is available.

CI runners have no step binary, so these tests skip there; they run in any
environment where `step` is on PATH (the sandbox used to develop the script).
"""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
STEP = shutil.which("step")
if STEP is None and os.environ.get("REQUIRE_STEP_CLI"):
    raise RuntimeError("REQUIRE_STEP_CLI is set but no `step` binary is on PATH; these tests must run, not skip")
pytestmark = pytest.mark.skipif(STEP is None, reason="step CLI not on PATH")


def _run(tmp: Path, **env_over) -> subprocess.CompletedProcess:
    env = dict(os.environ, STEPPATH=str(tmp / "online"), OFFLINE=str(tmp / "offline"),
               LAB_CA_TEMPLATE_DIR=str(REPO / "pki"), LAB_CA_HOST="ca.lab.example.net",
               LAB_CA_DOMAIN="lab.example.net", LAB_CA_PORT="9443")
    env.update(env_over)
    (tmp / "offline").mkdir(exist_ok=True)
    return subprocess.run(["bash", str(REPO / "pki" / "lab-ca-init.sh")], env=env,
                          capture_output=True, text=True, timeout=120)


def test_init_leaves_only_the_intermediate_key_online(tmp_path):
    r = _run(tmp_path)
    assert r.returncode == 0, r.stderr + r.stdout
    online, offline = tmp_path / "online", tmp_path / "offline"
    assert sorted(p.name for p in (online / "secrets").iterdir()) == ["intermediate_ca_key", "password"]
    assert (offline / "root_ca_key").is_file() and (offline / "root_password").is_file()
    assert (online / "certs" / "root-key-offline").is_file()
    meta = (online / "config" / "lab-ca.meta").read_text()
    assert "LAB_CA_HOST=ca.lab.example.net" in meta and "LAB_CA_PORT=9443" in meta
    ca = (online / "config" / "ca.json").read_text()
    assert '"idpURL": "https://ca.lab.example.net:9443/1.0/crl"' in ca
    assert "crlDistributionPoints" in ca and '"dns-01"' in ca and '":9443"' in ca
    inter = subprocess.run([STEP, "certificate", "inspect", str(online / "certs" / "intermediate_ca.crt"),
                            "--format", "text"], capture_output=True, text=True).stdout
    assert "Name Constraints: critical" in inter and "lab.example.net" in inter


def test_rerun_is_noop_and_drift_fails_closed(tmp_path):
    assert _run(tmp_path).returncode == 0
    again = _run(tmp_path)
    assert again.returncode == 0 and "nothing to do" in again.stdout
    drift = _run(tmp_path, LAB_CA_DOMAIN="other.example.net", LAB_CA_HOST="ca.other.example.net")
    assert drift.returncode == 3 and "differs" in drift.stderr
    port = _run(tmp_path, LAB_CA_PORT="9000")
    assert port.returncode == 3 and "LAB_CA_PORT" in port.stderr


def test_host_outside_domain_is_refused(tmp_path):
    r = _run(tmp_path, LAB_CA_HOST="ca.other.net")
    assert r.returncode == 2 and not (tmp_path / "online" / "config").exists()


def test_interrupted_init_is_resumed(tmp_path):
    """Fault-inject right after `step ca init`: the next run discards the partial state and completes."""
    broken = _run(tmp_path, LAB_CA_FAULT="after-init")
    assert broken.returncode == 99 and "fault injected" in broken.stderr
    online = tmp_path / "online"
    assert (online / "config" / "ca.json").is_file() and not (online / "config" / "lab-ca.meta").exists()
    assert (online / "config" / ".init-in-progress").is_file()
    again = _run(tmp_path)
    assert again.returncode == 0, again.stderr + again.stdout
    assert "interrupted" in again.stdout and "Lab CA initialised" in again.stdout
    assert (online / "config" / "lab-ca.meta").is_file() and not (online / "config" / ".init-in-progress").exists()
    assert sorted(p.name for p in (online / "secrets").iterdir()) == ["intermediate_ca_key", "password"]
    # the offline root was reused, not regenerated
    assert (tmp_path / "offline" / "root_ca_key").is_file()
    assert _run(tmp_path).returncode == 0


def test_provisioner_name_is_the_fixed_constant(tmp_path):
    from app import config
    assert _run(tmp_path).returncode == 0
    ca = (tmp_path / "online" / "config" / "ca.json").read_text()
    assert f'"name": "{config.LAB_CA_PROVISIONER}"' in ca and config.LAB_CA_PROVISIONER == "lab"
