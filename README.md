# Orchestrator ACME Certificate Manager

Automated TLS certificate lifecycle management for **HPE Aruba Networking EdgeConnect SD‑WAN Orchestrator**.

This tool issues, deploys, activates, and renews a publicly trusted HTTPS certificate for an Orchestrator appliance. It obtains certificates from [Let's Encrypt](https://letsencrypt.org/) over the ACME protocol using a Cloudflare DNS‑01 challenge, uploads them through the Orchestrator REST API, activates them with a graceful service reload, and **verifies the appliance is actually serving the new certificate**, rolling back to the last known good certificate if anything goes wrong. Everything runs in a single Docker container and is managed from a browser dashboard.

It is the Orchestrator counterpart to the [ClearPass ACME Certificate Manager](https://github.com/sinemad/cppm-acme-cert-manager); the two tools share a design and can run side by side on the same host.

> **Scope / status:** built and validated in a lab against production Let's Encrypt. It is intended for internal/lab use behind a trusted network boundary. Read the [Security Considerations](#security-considerations) before running it anywhere less private.

---

## Table of Contents

- [Features](#features)
- [Prerequisites](#prerequisites)
- [Directory Structure](#directory-structure)
- [Initial Setup](#initial-setup)
- [How It Works](#how-it-works)
- [Configuration Reference](#configuration-reference)
- [Web UI](#web-ui)
- [Maintenance](#maintenance)
- [Troubleshooting](#troubleshooting)
- [Security Considerations](#security-considerations)
- [Orchestrator API Reference](#orchestrator-api-reference)
- [License](#license)

---

## Features

- **Full lifecycle, unattended**: issue → deploy → activate, on a schedule (twice daily by default) or on demand.
- **DNS‑01 via Cloudflare**: works for appliances with no public inbound reachability; supports private hosts.
- **Verified activation**: after reloading the web service, the tool reads the certificate the appliance is *actually serving* and confirms its serial matches what was installed. "Port is up" is not treated as success.
- **Automatic rollback**: if activation can't be verified, the previous working certificate is re‑deployed and re‑verified, so a bad renewal never takes the appliance offline.
- **Rate‑limit‑safe re‑deploy**: a **Force deploy** action re‑pushes the certificate already on disk without contacting the CA, so you can recover a deployment without spending a Let's Encrypt issuance.
- **Web dashboard**: certificate status, expiry, days‑left, and renewal history at a glance; add/edit/delete servers; toggle staging↔production; manage secrets.
- **Per‑server secrets with env fallback**: the Cloudflare token and Orchestrator API key can be stored per server (never echoed back to the browser) or supplied via environment variables.
- **Authentication**: a first‑run Setup flow and a login gate protect the dashboard and settings.
- **Failure alerts**: a webhook (email, Slack, etc.) fires when a renewal fails.

---

## Prerequisites

- **Docker** and **Docker Compose** on a Linux host that can reach the internet and the Orchestrator.
- A **domain in Cloudflare** for the appliance's hostname, plus a **Cloudflare API token** scoped to *Edit zone DNS* for that zone.
- An **EdgeConnect Orchestrator** with:
  - a **Read‑Write API key** (Orchestrator → *Users & Authentication → API Keys*), and
  - **SSH access** for the activation restart, using key authentication (the restart user needs passwordless `sudo` scoped to the service restart and the `nginx` reload).
- A **DNS A record** for the appliance hostname pointing at the Orchestrator (DNS‑only, not proxied).
- Recommended: run the container on a host that reaches the Orchestrator over its management address, and reach the web UI over an **SSH tunnel** (the UI binds to localhost by default).

---

## Directory Structure

```
orchestrator-acme-cert-manager/
├── app/
│   ├── cli.py                 # CLI entry (renew-all) run by the scheduler
│   ├── config.py              # load/save servers.json; secret resolution (inline → env)
│   ├── issue.py               # stage 1 — Lego ACME issuance (DNS-01 / Cloudflare)
│   ├── deploy.py              # stage 2 — upload via Orchestrator httpsCertificate API
│   ├── restart.py             # stage 3 — SSH restart + served-cert verify + rollback
│   ├── renew.py               # orchestrates the three stages; records history; alerts
│   ├── store.py               # renewal history persistence (history.json)
│   ├── notify.py              # webhook failure alerts
│   ├── models.py              # ServerConfig, StepResult, RenewalRecord
│   ├── entrypoint.sh          # starts supercronic + the web server
│   └── webui/
│       ├── server.py          # Flask app: dashboard, API, settings CRUD, auth
│       ├── auth.py            # PBKDF2 login + HMAC-signed sessions
│       ├── templates/         # index, settings, server_form, login, setup
│       └── static/style.css
├── config/
│   ├── crontab                # supercronic schedule (02:00 / 14:00)
│   └── servers.example.json   # copy → servers.json (or manage via the web UI)
├── data/                      # runtime state (gitignored): certs, logs, ssh, history.json
├── Dockerfile
├── docker-compose.yml
├── docker-compose.override.yml.example
├── .env.example               # copy → .env
├── requirements.txt
└── setup.sh
```

`config/` and `data/` are **bind‑mounted** into the container so state survives rebuilds. `config/` must be mounted as a **directory** (not a single file) and must be **writable**; the web UI writes `servers.json` there. See [Troubleshooting](#the-web-ui-returns-500-on-save-readonly-file-system).

---

## Initial Setup

### 1. Clone the repository

```bash
git clone https://github.com/<you>/orchestrator-acme-cert-manager.git
cd orchestrator-acme-cert-manager
```

### 2. Host preparation

Create the runtime directories and drop in the SSH key used for the activation restart:

```bash
mkdir -p data/certs data/logs data/ssh
cp /path/to/orch_restart_key data/ssh/orch_restart
chmod 600 data/ssh/orch_restart
```

### 3. Configure environment (optional but recommended)

```bash
cp .env.example .env
```

Edit `.env`. At minimum, it should contain:

```dotenv
SERVERS_FILE=/config/servers.json
# Fallbacks used when a server has no inline secret set in the web UI:
CF_DNS_API_TOKEN=your-cloudflare-token
ORCH_API_KEY=your-orchestrator-api-key
# Optional failure webhook:
NOTIFY_WEBHOOK_URL=
```

> **Notes:** keep values **unquoted**. If you edited `.env` on Windows, strip carriage returns: `sed -i 's/\r$//' .env`. You can leave `CF_DNS_API_TOKEN`/`ORCH_API_KEY` blank and enter them per server in the web UI instead. The inline value wins, the env var is the fallback.

### 4. Configure the server (or do it in the UI after first run)

```bash
cp config/servers.example.json config/servers.json
```

Edit `config/servers.json` (see the [Configuration Reference](#configuration-reference)), **or** skip this and add the server from the web UI after the container is up.

### 5. Build and start

```bash
docker compose up -d --build
docker compose ps        # container should read "Up (a few seconds ago)"
```

### 6. Create the admin account

The web UI binds to `127.0.0.1:8090` by default. Open an SSH tunnel from your workstation:

```bash
ssh -i /path/to/key -L 8090:localhost:8090 <user>@<docker-host>
```

Then browse to **http://localhost:8090**. On first run you'll be sent to a **Setup** page — create the single administrator account (password ≥ 8 characters). You'll land on the dashboard, signed in.

### 7. Add / verify the server and issue the first certificate

In the web UI, open **Settings**, add or confirm your Orchestrator, and set its **CA to *Let's Encrypt (staging)*** for the first run. On the dashboard, click **Force renew**.

- A **staging** run proves the pipeline end to end without spending production rate limits; the resulting cert chains to an untrusted staging root, so browsers will still warn; that's expected.
- Once staging is green (issue → deploy → activate), switch the CA to **production** and Force renew again for the real, trusted certificate.
- Verify from a device **outside** your network (e.g. a phone on cellular): browse to `https://<appliance-host>` and confirm a clean padlock.

---

## How It Works

### The pipeline

Each renewal runs three stages in order and **stops on the first failure**, so a half‑finished renewal never reaches the appliance:

1. **Issue** (`issue.py`) — runs the [Lego](https://go-acme.github.io/lego/) ACME client: `lego run` with a Cloudflare DNS‑01 challenge against Let's Encrypt. The tool injects the resolved Cloudflare token into Lego's environment, requests (or renews) the certificate, and flattens Lego's output into three canonical files: `<domain>.cer` (leaf), `<domain>.key` (private key), and `ca.cer` (issuer chain). `--ari-disable` is passed to avoid a renewal‑info mismatch when a certificate from the *other* environment is present on disk (see [Troubleshooting](#lego-fails-with-an-ari-replaces--404-error)).
2. **Deploy** (`deploy.py`) — uploads the certificate to the Orchestrator `httpsCertificate` REST API as a base64 data‑URI JSON payload, authenticating with the API key (`X-Auth-Token`): first a validation call, then the install.
3. **Activate + verify** (`restart.py`) — over SSH, restarts the Orchestrator service and reloads `nginx`, then polls the appliance on `:443` and compares the **served certificate's serial** to the one just deployed. On success the certificate is snapshotted as the new known‑good; on failure the tool re‑deploys the previous known‑good certificate and re‑verifies.

`renew.py` coordinates the stages, writes a record of every run to the history store, and sends a failure alert. It also exposes **`redeploy_server()`** (the *Force deploy* path) which runs **deploy → activate only**, skipping issuance entirely (and therefore never contacting the CA).

### Scheduled renewal

`supercronic` reads `config/crontab` and triggers a renewal at **02:00 and 14:00**. Each scheduled run only renews a certificate that is within its renewal window (≈30 days of expiry); otherwise it does nothing, so running twice a day is safe and cheap.

### Authentication

The web UI uses a single admin account. Passwords are hashed with PBKDF2‑SHA256; sessions are HMAC‑signed cookies with an 8‑hour lifetime. The credential (`admin.json`) and signing key (`session.secret`) are written `chmod 600` into the `/config` volume, so logins survive rebuilds. Until an admin exists, every route redirects to the Setup page.

### Certificate files

For each server, under `data/certs/<domain>/`:

| File            | Contents                                           |
|-----------------|----------------------------------------------------|
| `<domain>.cer`  | leaf (end‑entity) certificate                      |
| `<domain>.key`  | private key (`chmod 600`)                          |
| `ca.cer`        | issuer chain (intermediate + root)                 |
| `certificates/` | Lego's own working directory and ACME account      |
| `rollback/`     | last known‑good snapshot used by the rollback path |

---

## Configuration Reference

### `config/servers.json`

A JSON object with a `servers` array. One entry per Orchestrator:

```json
{
  "servers": [
    {
      "id": "orch-lab",
      "name": "Lab Orchestrator",
      "orchestrator_host": "orchestrator.example.com",
      "domain": "orchestrator.example.com",
      "verify_ssl": false,
      "acme": {
        "ca": "letsencrypt_test",
        "email": "you@example.com",
        "key_type": "rsa2048"
      },
      "dns": {
        "provider": "cloudflare",
        "api_token": ""
      },
      "ssh": {
        "user": "admin",
        "key_path": "/data/ssh/orch_restart",
        "known_hosts": "/data/ssh/known_hosts",
        "port": 22,
        "restart_command": "sudo systemctl restart --no-block gms.service",
        "nginx_reload_command": "sudo systemctl reload nginx"
      },
      "api_key_env": "ORCH_API_KEY",
      "api_key": ""
    }
  ]
}
```

| Field               | Meaning                                                                                                   |
|---------------------|-----------------------------------------------------------------------------------------------------------|
| `id`                | Unique slug (letters, numbers, `-`, `_`). Permanent, can't be renamed.                                    |
| `name`              | Display name shown in the dashboard.                                                                      |
| `orchestrator_host` | FQDN the API calls and SSH target.                                                                        |
| `domain`            | Hostname the certificate is issued for (defaults to the host).                                            |
| `verify_ssl`        | Verify the Orchestrator's own TLS cert on API calls. Leave `false` for a self‑signed/pre‑replacement box. |
| `acme.ca`           | `letsencrypt` (production) or `letsencrypt_test` (staging). A full ACME directory URL is also accepted.   |
| `acme.email`        | Account email for Let's Encrypt (required).                                                               |
| `acme.key_type`     | `rsa2048`, `rsa3072`, or `rsa4096`. Orchestrator serves a single RSA cert.                                |
| `dns.provider`      | Only `cloudflare` is wired up today.                                                                      |
| `dns.api_token`     | Inline Cloudflare token. Blank → fall back to `CF_DNS_API_TOKEN`.                                         |
| `ssh.*`             | SSH user/key/port and the restart + nginx‑reload commands run to activate.                                |
| `api_key_env`       | Name of the env var holding the Orchestrator API key when `api_key` is blank.                             |
| `api_key`           | Inline Orchestrator API key. Blank → fall back to the env var above.                                      |

> Secrets (`dns.api_token`, `api_key`) are optional. Set them in the web UI or here; either way the file is written `chmod 600`. **`config/servers.json` is gitignored** and must never be committed.

### Environment (`.env`)

| Variable             | Purpose                                                                     |
|----------------------|-----------------------------------------------------------------------------|
| `SERVERS_FILE`       | Path to the config inside the container. **Set to `/config/servers.json`.** |
| `CF_DNS_API_TOKEN`   | Cloudflare token fallback (used when a server has no inline token).         |
| `ORCH_API_KEY`       | Orchestrator API key fallback.                                              |
| `NOTIFY_WEBHOOK_URL` | Optional Slack‑compatible webhook for failure alerts.                       |
| `RENEW_WINDOW_DAYS`  | Days‑before‑expiry to renew on the scheduled path (default 30).             |

### Volumes (`docker-compose.yml`)

```yaml
    ports:
      - "127.0.0.1:8090:8080"   # localhost only; reach via SSH tunnel
    volumes:
      - ./config:/config        # writable directory mount — holds servers.json, admin.json, session.secret
      - ./data/certs:/data/certs
      - ./data/logs:/data/logs
      - ./data/ssh:/data/ssh:ro
```

> `config/` **must** be a directory mount, not a single‑file mount, and must not be read‑only. See the [500 on save](#the-web-ui-returns-500-on-save-readonly-file-system) troubleshooting entry.

---

## Web UI

Reached at `http://localhost:8090` over the SSH tunnel.

### Pages

- **Dashboard** (`/`) — a card per server showing CA, expiry, days‑left, serial, and last‑run outcome, plus a renewal‑history table. Two actions per server: **Force renew** (full pipeline) and **Force deploy** (re‑push the on‑disk cert, no CA call).
- **Settings** (`/settings`) — list, **add**, **edit**, and **delete** servers. The edit form includes the **CA staging↔production** dropdown and the two secret fields (Cloudflare token, API key). Stored secrets are never displayed back; leave a secret field blank to keep the existing value, or type a new one to replace it.
- **Setup / Login** — first‑run admin creation, then a login gate on everything else.

### Live configuration

Because `config.py` reads `servers.json` on every request, **changes made in the UI take effect on the next run. No rebuild or restart.** (Deploying new *code* still requires an image rebuild.)

---

## Maintenance

### View logs

```bash
# Web dashboard (easiest) — renewal history is on the main page
# Scheduled-run log:
tail -n 100 data/logs/renew.log
# Container output (includes web + scheduler):
docker compose logs -f --tail 100
```

### Force a renewal or re‑deploy

Use the dashboard buttons: **Force renew** (contacts the CA) or **Force deploy** (re‑pushes the existing cert, rate‑limit‑immune). Force deploy is the right choice after an appliance rebuild or to recover a deployment without spending an issuance.

### Switch staging ↔ production

**Settings → edit the server → CA dropdown → Save.** No rebuild needed. Remember staging certs are browser‑untrusted; production is the resting state.

### Reset the admin account

If the password is lost, remove the credential and reload. The tool drops back into Setup:

```bash
rm config/admin.json
```

### Rebuild the image (state preserved)

Application code is baked into the image, so **code changes require a rebuild**:

```bash
docker compose up -d --build
# or, if a change isn't picked up:
docker compose down && docker compose build --no-cache && docker compose up -d
```

Certificates, history, and config live in the mounted volumes and are preserved across rebuilds. A volume or `.env`/compose change requires `docker compose down && up -d` (not just `--build`).

---

## Troubleshooting

Failures are recorded in the dashboard history with the underlying error message. For anything not obvious there, `docker compose logs -f` shows the full output.

### The web UI returns 500 on save ("Read‑only file system")

`config/servers.json` is mounted read‑only or as a single file. Docker won't let the app write a single‑file bind mount, and a `:ro` flag makes it read‑only. **Mount the directory, writable**, and point the app at it:

```yaml
    volumes:
      - ./config:/config        # NOT  ./config/servers.json:/data/servers.json:ro
```
```dotenv
SERVERS_FILE=/config/servers.json
```

Recreate the container (`docker compose down && up -d`) and confirm it's writable:
```bash
docker compose exec <service> sh -lc 'touch /config/.w && echo WRITABLE && rm /config/.w'
```

### `lego issue failed (exit 1)` with an empty error

Lego writes some errors to **stdout**, not stderr; the tool captures both, so the dashboard message should show the real last line. Common causes:

- **No Cloudflare token in the container**: the fastest failure (dies in well under a second at startup). Set the token per server in the UI, or put `CF_DNS_API_TOKEN` in `.env` and `docker compose up -d --force-recreate`. Verify: `docker compose exec <service> sh -lc 'env | grep CF_DNS_API_TOKEN'`.
- **Wrong Lego flag layout**: this build is Lego 5.3.1: everything is a `run` flag, there is no `renew` subcommand, and forcing uses `--renew-force`. Check with `lego run --help`.
- **Rate limit**: see below.

### Lego fails with an ARI `replaces` / 404 error

`Could not validate ARI 'replaces' field … Authority Key Identifier that did not match a known issuer` happens when a certificate issued by the **other** environment (e.g. a staging cert) is on disk and you're now issuing against **production** (or vice versa). The tool passes `--ari-disable` to prevent this. If you still hit it after switching environments, clear the stale cert so the next run is a fresh issue:

```bash
docker compose exec <service> sh -lc \
  'cd /data/certs/<domain> && mkdir -p _old && mv <domain>.* ca.cer certificates/_old/ 2>/dev/null; ls'
```

### Let's Encrypt rate limit (HTTP 429)

Production allows only a limited number of duplicate certificates per week. To recover without re‑issuing, use **Force deploy** (re‑pushes the on‑disk cert, no CA contact). For iterating, use the **staging** CA, which has far higher limits. Then wait out the window before the next production issue.

### Certificate installed but the appliance still serves the old one

`nginx` caches the certificate in memory, so a reload is required to serve a new one, which is why the activate stage reloads `nginx` and then verifies the served serial. If verification keeps failing, confirm the restart user can actually run the reload command over SSH and that the reload succeeds.

### SSH restart hangs the run

Use a **non‑blocking** service restart (`systemctl restart --no-block gms.service`) so the SSH session returns immediately, and ensure the restart user has **passwordless `sudo`** scoped to both the service restart and the `nginx` reload.

### Config changes or code changes "don't take"

- **Config** (servers, CA, secrets) is read live from `servers.json`. No rebuild needed, provided the mount is writable (above).
- **Code** is copied into the image at build time, you must `docker compose up -d --build` (or `--no-cache`). Confirm the running container has the new code: `docker compose exec <service> grep -c <a-new-string> /app/app/<file>`.

### `curl http://localhost:8090/api/...` now redirects to `/login`

Expected — the API is behind auth. Use the unauthenticated health check, or log in first:

```bash
curl -s http://localhost:8090/healthz                      # {"status":"ok"}
curl -c jar -d 'username=admin&password=…' http://localhost:8090/login
curl -b jar http://localhost:8090/api/servers
```

### Container exits immediately

Check `docker compose logs`. Usual causes: a malformed `servers.json` (validate with `python3 -c "import json;json.load(open('config/servers.json'))"`), a bad `.env` (CRLF or quoted values), or `SERVERS_FILE` pointing somewhere unmounted.

---

## Security Considerations

- **Secrets at rest**: With inline secrets, `servers.json` (and its `.bak`) contain a Cloudflare token and Orchestrator API key. They're written `chmod 600`. `config/servers.json`, `.env`, `config/admin.json`, and `config/session.secret` are gitignored; never commit them. Anyone with file access to the host can read them. A secrets vault is the recommended hardening step.
- **Network exposure**: The UI binds to `127.0.0.1` and is intended to be reached over an SSH tunnel. Do not publish port 8090. Auth is a second layer, not a substitute for keeping the port private.
- **Least privilege**: Scope the Cloudflare token to *Edit zone DNS* on the single zone. Use an Orchestrator API key with the minimum role that can install a certificate. The SSH restart key should be dedicated and its user's `sudo` scoped to just the restart/reload commands.
- **Private key handling**: Keys are generated on the automation host and pushed to the appliance. For stricter environments, prefer on‑appliance key generation and per‑renewal key rotation.

---

## Orchestrator API Reference

The deploy stage uses the Orchestrator `httpsCertificate` REST API, authenticating with `X-Auth-Token: <api-key>`:

| Call                                              | Purpose                                                    |
|---------------------------------------------------|------------------------------------------------------------|
| `POST …/gms/rest/gms/httpsCertificate/validation` | Validate the certificate/key/chain payload before install. |
| `POST …/gms/rest/gms/httpsCertificate`            | Install the validated certificate.                         |

The payload is a JSON object carrying the leaf certificate, private key, and intermediate chain as base64 `data:` URIs (`certificateData`, `keyData`, `intermediateCertFileContent`). Activation is **not** an API call, it's an SSH service restart plus `nginx` reload, followed by a served‑certificate check on `:443`.

---

## License

MIT — see [LICENSE](LICENSE).
