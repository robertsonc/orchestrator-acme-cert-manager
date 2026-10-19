#!/usr/bin/env bash
# =============================================================================
# setup.sh — host preparation for orchestrator-acme-cert-manager
#
# Idempotent. Run it again any time; it only creates what is missing.
#
#   1. Installs Docker Engine + the Compose plugin if they are missing.
#   2. Creates the data/config layout with restrictive permissions.
#   3. Generates a dedicated SSH key pair for the activation step.
#   4. Writes .env and config/servers.json from the examples (if absent).
#   5. Pins the Orchestrator SSH host key (you confirm the fingerprint).
#   6. Installs the public key on the Orchestrator account.
#   7. Checks (optionally installs) the scoped NOPASSWD sudoers rule.
#   8. Verifies key authentication + sudo authorization end to end.
#
# Nothing in this script restarts or reloads any service on the Orchestrator.
# The only writes to the appliance are: appending one line to
# ~/.ssh/authorized_keys (step 6) and, only with --install-sudoers and after an
# explicit confirmation, one drop-in file under /etc/sudoers.d (step 7).
# =============================================================================
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
data="${here}/data"
cfg="${here}/config"
ssh_dir="${data}/ssh"
key_file="${ssh_dir}/orch_restart"
known_hosts="${ssh_dir}/known_hosts"
container_key="/data/ssh/orch_restart"
container_known_hosts="/data/ssh/known_hosts"
sudoers_name="orchestrator-acme-cert-manager"

# ---- options (flags override env, env overrides defaults) --------------------
ORCH_HOST="${ORCH_HOST:-}"
ORCH_SSH_USER="${ORCH_SSH_USER:-admin}"
ORCH_SSH_PORT="${ORCH_SSH_PORT:-22}"
ORCH_SERVER_ID="${ORCH_SERVER_ID:-orch-1}"
ORCH_SERVER_NAME="${ORCH_SERVER_NAME:-}"
ORCH_DOMAIN="${ORCH_DOMAIN:-}"
ACME_EMAIL="${ACME_EMAIL:-}"
ORCH_RESTART_CMD="${ORCH_RESTART_CMD:-/bin/systemctl restart --no-block gms.service}"
ORCH_NGINX_RELOAD_CMD="${ORCH_NGINX_RELOAD_CMD:-/bin/systemctl reload nginx}"
KEY_TYPE="${KEY_TYPE:-rsa}"
non_interactive=0
trust_host_key=0
skip_docker=0
skip_remote=0
install_sudoers=0
start_stack=0
ssh_tgt=""

usage() {
  cat <<EOF
Usage: ./setup.sh [options]

Target:
  --host HOST            Orchestrator hostname (FQDN preferred; used for SSH, API and the certificate)
  --domain DOMAIN        Certificate domain (default: same as --host)
  --ssh-user USER        SSH login on the Orchestrator (default: ${ORCH_SSH_USER})
  --ssh-port PORT        SSH port (default: ${ORCH_SSH_PORT})
  --server-id ID         Config entry id, letters/digits/-/_ (default: ${ORCH_SERVER_ID})
  --name NAME            Display name (default: the host)
  --email EMAIL          ACME account email (required to write servers.json)
  --key-type rsa|ed25519 SSH key type to generate (default: rsa, 4096 bit — tested against Orchestrator)

Behaviour:
  --non-interactive      Never prompt. Docker install is auto-approved; anything needing a human
                         (host-key confirmation without --trust-host-key, password-based key install)
                         is reported and skipped.
  --trust-host-key       Pin the scanned host key without prompting. ONLY when you have already
                         verified the fingerprint out of band.
  --install-sudoers      Offer to write the scoped NOPASSWD rule to /etc/sudoers.d on the Orchestrator
                         (shows the exact content, asks for confirmation, validates with visudo).
  --skip-docker          Do not install Docker.
  --skip-remote          Do not connect to the Orchestrator (prints the manual steps instead).
  --start                Run 'docker compose up -d --build' at the end.
  -h, --help             This text.

Environment equivalents: ORCH_HOST ORCH_DOMAIN ORCH_SSH_USER ORCH_SSH_PORT ORCH_SERVER_ID
                         ORCH_SERVER_NAME ACME_EMAIL ORCH_RESTART_CMD ORCH_NGINX_RELOAD_CMD KEY_TYPE
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --host) ORCH_HOST="$2"; shift 2 ;;
    --domain) ORCH_DOMAIN="$2"; shift 2 ;;
    --ssh-user) ORCH_SSH_USER="$2"; shift 2 ;;
    --ssh-port) ORCH_SSH_PORT="$2"; shift 2 ;;
    --server-id) ORCH_SERVER_ID="$2"; shift 2 ;;
    --name) ORCH_SERVER_NAME="$2"; shift 2 ;;
    --email) ACME_EMAIL="$2"; shift 2 ;;
    --key-type) KEY_TYPE="$2"; shift 2 ;;
    --non-interactive) non_interactive=1; shift ;;
    --trust-host-key) trust_host_key=1; shift ;;
    --install-sudoers) install_sudoers=1; shift ;;
    --skip-docker) skip_docker=1; shift ;;
    --skip-remote) skip_remote=1; shift ;;
    --start) start_stack=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# ---- helpers -----------------------------------------------------------------
c_bold=$'\e[1m'; c_ok=$'\e[32m'; c_warn=$'\e[33m'; c_err=$'\e[31m'; c_off=$'\e[0m'
if [[ ! -t 1 ]]; then c_bold=""; c_ok=""; c_warn=""; c_err=""; c_off=""; fi
step() { printf '\n%s==> %s%s\n' "$c_bold" "$*" "$c_off"; }
ok()   { printf '%s  ✓ %s%s\n' "$c_ok" "$*" "$c_off"; }
warn() { printf '%s  ! %s%s\n' "$c_warn" "$*" "$c_off"; }
err()  { printf '%s  ✗ %s%s\n' "$c_err" "$*" "$c_off" >&2; }
die()  { err "$@"; exit 1; }
have() { command -v "$1" >/dev/null 2>&1; }

# ask "question" -> 0 yes / 1 no. Non-interactive: always "no" unless $2 == default-yes.
ask() {
  local q="$1" dflt="${2:-no}" a
  if [[ $non_interactive -eq 1 ]]; then [[ "$dflt" == "yes" ]]; return; fi
  if [[ "$dflt" == "yes" ]]; then read -r -p "  $q [Y/n] " a; [[ -z "$a" || "$a" =~ ^[Yy] ]]
  else read -r -p "  $q [y/N] " a; [[ "$a" =~ ^[Yy] ]]; fi
}

# prompt_var VAR "question" "default" — only when interactive and VAR is empty
prompt_var() {
  local -n ref="$1"; local q="$2" dflt="${3:-}" a
  [[ -n "$ref" || $non_interactive -eq 1 ]] && return 0
  if [[ -n "$dflt" ]]; then read -r -p "  $q [$dflt]: " a; ref="${a:-$dflt}"
  else read -r -p "  $q: " a; ref="$a"; fi
}

sudo_cmd() { if [[ $EUID -eq 0 ]]; then "$@"; else sudo "$@"; fi; }

validate_inputs() {
  [[ "$ORCH_HOST" =~ ^[A-Za-z0-9.-]+$ ]]      || die "invalid --host '${ORCH_HOST}' (hostname or address only)"
  [[ "$ORCH_DOMAIN" =~ ^[A-Za-z0-9.-]+$ ]]    || die "invalid --domain '${ORCH_DOMAIN}'"
  [[ "$ORCH_SSH_USER" =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid --ssh-user '${ORCH_SSH_USER}'"
  [[ "$ORCH_SSH_PORT" =~ ^[0-9]+$ && $ORCH_SSH_PORT -ge 1 && $ORCH_SSH_PORT -le 65535 ]] || die "invalid --ssh-port '${ORCH_SSH_PORT}'"
  [[ "$ORCH_SERVER_ID" =~ ^[A-Za-z0-9_-]+$ ]] || die "invalid --server-id '${ORCH_SERVER_ID}'"
  [[ -z "$ACME_EMAIL" || "$ACME_EMAIL" =~ ^[^[:space:]\"\\]+@[^[:space:]\"\\]+$ ]] || die "invalid --email '${ACME_EMAIL}'"
  [[ "$KEY_TYPE" == "rsa" || "$KEY_TYPE" == "ed25519" ]] || die "--key-type must be rsa or ed25519"
  [[ "$ORCH_SERVER_NAME" != *'"'* && "$ORCH_SERVER_NAME" != *'\'* ]] || die "--name may not contain quotes or backslashes"
}

kh_name() { if [[ "$ORCH_SSH_PORT" == "22" ]]; then echo "$ORCH_HOST"; else echo "[${ORCH_HOST}]:${ORCH_SSH_PORT}"; fi; }

# Batch-mode options for every unattended ssh call (set once the key/known_hosts exist).
ssh_opts=()
set_ssh_opts() {
  ssh_opts=(-i "$key_file" -p "$ORCH_SSH_PORT"
            -o BatchMode=yes -o IdentitiesOnly=yes -o PasswordAuthentication=no
            -o UserKnownHostsFile="$known_hosts" -o StrictHostKeyChecking=yes
            -o ConnectTimeout=15)
  ssh_tgt="${ORCH_SSH_USER}@${ORCH_HOST}"
}

# ---- 1. Docker ---------------------------------------------------------------
docker_ok() { have docker && docker compose version >/dev/null 2>&1; }

install_docker() {
  local id="" like="" ver=""
  if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    id="${ID:-}"; like="${ID_LIKE:-}"; ver="${VERSION_CODENAME:-}"
  fi
  if [[ "$id" == "ubuntu" || "$id" == "debian" ]]; then
    local arch; arch="$(dpkg --print-architecture)"
    sudo_cmd apt-get update -qq
    sudo_cmd apt-get install -y -qq ca-certificates curl gnupg
    sudo_cmd install -m 0755 -d /etc/apt/keyrings
    curl -fsSL "https://download.docker.com/linux/${id}/gpg" | sudo_cmd gpg --dearmor --yes -o /etc/apt/keyrings/docker.gpg
    sudo_cmd chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=${arch} signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/${id} ${ver} stable" \
      | sudo_cmd tee /etc/apt/sources.list.d/docker.list >/dev/null
    sudo_cmd apt-get update -qq
    sudo_cmd apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  elif [[ "$id" =~ ^(fedora|rhel|centos|rocky|almalinux)$ || "$like" == *rhel* || "$like" == *fedora* ]]; then
    local pm="dnf"; have dnf || pm="yum"
    local repo_os="centos"; [[ "$id" == "fedora" ]] && repo_os="fedora"; [[ "$id" == "rhel" ]] && repo_os="rhel"
    sudo_cmd "$pm" -y install "${pm}-plugins-core" >/dev/null 2>&1 || true
    if have dnf; then sudo_cmd dnf config-manager --add-repo "https://download.docker.com/linux/${repo_os}/docker-ce.repo"
    else sudo_cmd yum-config-manager --add-repo "https://download.docker.com/linux/${repo_os}/docker-ce.repo"; fi
    sudo_cmd "$pm" -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  else
    die "unsupported distribution '${id:-unknown}' for automatic Docker install. Install Docker Engine + the Compose plugin per https://docs.docker.com/engine/install/ and re-run with --skip-docker."
  fi
  if have systemctl; then
    sudo_cmd systemctl enable --now docker
  fi
}

ensure_docker() {
  step "Docker"
  if [[ $skip_docker -eq 1 ]]; then warn "skipping Docker check (--skip-docker)"; return; fi
  if docker_ok; then ok "docker $(docker --version | sed 's/Docker version //') with compose plugin present"; return; fi
  if have docker; then warn "docker is installed but the 'docker compose' plugin is missing"
  else warn "docker is not installed"; fi
  if ! ask "Install Docker Engine + Compose plugin from Docker's official repository now?" yes; then
    die "Docker is required. Install it (https://docs.docker.com/engine/install/) or re-run with --skip-docker."
  fi
  install_docker
  docker_ok || die "Docker install finished but 'docker compose version' still fails"
  ok "Docker installed: $(docker --version | sed 's/Docker version //')"
  if [[ $EUID -ne 0 ]] && ! id -nG "$USER" | tr ' ' '\n' | grep -qx docker; then
    sudo_cmd usermod -aG docker "$USER"
    warn "added $USER to the 'docker' group — log out and back in (or run 'newgrp docker') before using docker without sudo"
  fi
}

# ---- 2. directories ----------------------------------------------------------
ensure_dirs() {
  step "Directories"
  mkdir -p "${data}/certs" "${data}/logs" "$ssh_dir" "$cfg"
  chmod 700 "$ssh_dir" "${data}/certs"
  ok "created ${data}/{certs,logs,ssh} and ${cfg}"
}

# ---- 3. key pair -------------------------------------------------------------
ensure_key() {
  step "SSH key pair"
  have ssh-keygen || die "ssh-keygen not found — install the OpenSSH client package"
  if [[ -f "$key_file" ]]; then
    if ssh-keygen -y -P "" -f "$key_file" >/dev/null 2>&1; then
      ok "using existing key ${key_file}"
    else
      die "${key_file} exists but is passphrase-protected or unreadable. The unattended container needs a key without a passphrase; move it aside and re-run."
    fi
  else
    if [[ "$KEY_TYPE" == "rsa" ]]; then
      ssh-keygen -q -t rsa -b 4096 -N "" -C "orchestrator-acme-cert-manager" -f "$key_file"
    else
      ssh-keygen -q -t ed25519 -N "" -C "orchestrator-acme-cert-manager" -f "$key_file"
    fi
    ok "generated ${KEY_TYPE} key ${key_file}"
  fi
  [[ -f "${key_file}.pub" ]] || ssh-keygen -y -f "$key_file" > "${key_file}.pub"
  chmod 600 "$key_file"; chmod 644 "${key_file}.pub"
  ok "fingerprint: $(ssh-keygen -lf "${key_file}.pub" | awk '{print $2}')"
}

# ---- 4. .env + servers.json --------------------------------------------------
ensure_env() {
  step "Environment file"
  if [[ ! -f "${here}/.env" ]]; then
    cp "${here}/.env.example" "${here}/.env"; chmod 600 "${here}/.env"
    ok "created .env from .env.example — fill in CF_DNS_API_TOKEN and ORCH_API_KEY (or set them per server in the web UI)"
  else
    ok ".env present"
  fi
  if ! grep -q '^SERVERS_FILE=' "${here}/.env"; then
    printf '\nSERVERS_FILE=/config/servers.json\n' >> "${here}/.env"
    ok "added SERVERS_FILE=/config/servers.json to .env"
  elif ! grep -q '^SERVERS_FILE=/config/servers.json$' "${here}/.env"; then
    warn ".env sets SERVERS_FILE to something other than /config/servers.json — only /config is persistently mounted by docker-compose.yml"
  fi
}

ensure_servers_json() {
  step "Server configuration"
  local f="${cfg}/servers.json"
  if [[ -f "$f" ]]; then
    ok "${f} exists — not touched (edit it or use the web UI)"
    grep -q "\"$ORCH_HOST\"" "$f" || warn "it does not mention ${ORCH_HOST}; add the server in the web UI if needed"
    return
  fi
  if [[ -z "$ACME_EMAIL" ]]; then
    warn "no --email given; copying the example instead. Add your server in the web UI after first start."
    cp "${cfg}/servers.example.json" "$f"; chmod 600 "$f"; return
  fi
  local name="${ORCH_SERVER_NAME:-$ORCH_HOST}"
  cat > "$f" <<JSON
{
  "servers": [
    {
      "id": "${ORCH_SERVER_ID}",
      "name": "${name}",
      "orchestrator_host": "${ORCH_HOST}",
      "domain": "${ORCH_DOMAIN}",
      "api_key_env": "ORCH_API_KEY",
      "api_key": "",
      "verify_ssl": false,
      "ca_bundle": "",
      "acme": {"ca": "letsencrypt_test", "email": "${ACME_EMAIL}", "key_type": "rsa2048"},
      "dns": {"provider": "cloudflare", "api_token": ""},
      "ssh": {
        "user": "${ORCH_SSH_USER}",
        "key_path": "${container_key}",
        "known_hosts": "${container_known_hosts}",
        "port": ${ORCH_SSH_PORT},
        "restart_command": "sudo ${ORCH_RESTART_CMD}",
        "nginx_reload_command": "sudo ${ORCH_NGINX_RELOAD_CMD}"
      }
    }
  ]
}
JSON
  chmod 600 "$f"
  ok "wrote ${f} (CA = Let's Encrypt staging; switch to production in the web UI once a staging run is green)"
}

# ---- 5. host key -------------------------------------------------------------
ensure_known_hosts() {
  step "Orchestrator SSH host key"
  local name; name="$(kh_name)"
  touch "$known_hosts"; chmod 644 "$known_hosts"
  if ssh-keygen -F "$name" -f "$known_hosts" >/dev/null 2>&1; then
    ok "host key for ${name} already pinned in ${known_hosts}"
    return
  fi
  have ssh-keyscan || die "ssh-keyscan not found — install the OpenSSH client package"
  local tmp; tmp="$(mktemp)"
  if ! ssh-keyscan -p "$ORCH_SSH_PORT" -T 10 -t rsa,ecdsa,ed25519 "$ORCH_HOST" > "$tmp" 2>/dev/null || [[ ! -s "$tmp" ]]; then
    rm -f "$tmp"; die "ssh-keyscan returned nothing from ${ORCH_HOST}:${ORCH_SSH_PORT} — is SSH reachable from this host?"
  fi
  echo "  Host key fingerprints presented by ${name}:"
  ssh-keygen -lf "$tmp" | sed 's/^/    /'
  echo "  ssh-keyscan does NOT authenticate the appliance. Compare these with a fingerprint obtained"
  echo "  from the Orchestrator console or an administrator before trusting them."
  if [[ $trust_host_key -eq 1 ]] || ask "Do the fingerprints match the trusted reference? Pin them?"; then
    cat "$tmp" >> "$known_hosts"; rm -f "$tmp"
    ok "pinned ${name} in ${known_hosts}"
  else
    rm -f "$tmp"
    die "host key not pinned. Re-run after verifying the fingerprint (or pass --trust-host-key once verified)."
  fi
}

# ---- 6. authorized key -------------------------------------------------------
key_auth_works() {
  set_ssh_opts
  ssh "${ssh_opts[@]}" "$ssh_tgt" true >/dev/null 2>&1
}

print_manual_key_install() {
  cat <<EOF
  Install the public key manually on the Orchestrator as ${ORCH_SSH_USER}:

    umask 077; mkdir -p ~/.ssh
    echo '$(cat "${key_file}.pub")' >> ~/.ssh/authorized_keys
    chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys

  Only the public key goes on the appliance; the private key stays in ${ssh_dir}.
EOF
}

ensure_authorized_key() {
  step "Public key on the Orchestrator (${ORCH_SSH_USER}@${ORCH_HOST})"
  if key_auth_works; then ok "key authentication already works"; return; fi
  if [[ $non_interactive -eq 1 ]]; then
    warn "key authentication does not work yet and --non-interactive prevents a password prompt"
    print_manual_key_install; return
  fi
  echo "  Key authentication is not set up yet. The next step logs in with the account's password"
  echo "  (prompted by the appliance) and appends the public key to ~/.ssh/authorized_keys."
  if ! ask "Install the public key over SSH now?" yes; then print_manual_key_install; return; fi
  local tgt="${ORCH_SSH_USER}@${ORCH_HOST}"
  local common=(-p "$ORCH_SSH_PORT" -o UserKnownHostsFile="$known_hosts" -o StrictHostKeyChecking=yes -o ConnectTimeout=15)
  if have ssh-copy-id; then
    ssh-copy-id -i "${key_file}.pub" "${common[@]}" "$tgt" || { warn "ssh-copy-id failed"; print_manual_key_install; return; }
  else
    ssh "${common[@]}" -o PubkeyAuthentication=no "$tgt" \
      "umask 077; mkdir -p ~/.ssh; cat >> ~/.ssh/authorized_keys; chmod 700 ~/.ssh; chmod 600 ~/.ssh/authorized_keys" \
      < "${key_file}.pub" || { warn "remote append failed"; print_manual_key_install; return; }
  fi
  if key_auth_works; then ok "key authentication works"
  else warn "public key installed but key authentication still fails — check the account's sshd/AllowUsers/PubkeyAuthentication settings"; fi
}

# ---- 7. sudoers --------------------------------------------------------------
sudoers_line() { echo "${ORCH_SSH_USER} ALL=(root) NOPASSWD: ${ORCH_RESTART_CMD}, ${ORCH_NGINX_RELOAD_CMD}"; }

sudo_authorized() {
  set_ssh_opts
  ssh "${ssh_opts[@]}" "$ssh_tgt" "sudo -n -l ${ORCH_RESTART_CMD} >/dev/null 2>&1 && sudo -n -l ${ORCH_NGINX_RELOAD_CMD} >/dev/null 2>&1"
}

ensure_sudoers() {
  step "Passwordless sudo for the activation commands"
  if ! key_auth_works; then warn "skipped: key authentication is not working yet"; return; fi
  if sudo_authorized; then ok "sudo -n permits both commands for ${ORCH_SSH_USER}"; return; fi
  warn "sudo does not (yet) permit the commands without a password."
  echo "  An administrator must add this rule on the Orchestrator with visudo (for example as"
  echo "  /etc/sudoers.d/${sudoers_name}, mode 0440):"
  echo
  echo "    $(sudoers_line)"
  echo
  echo "  Verify the systemctl path on the appliance ('command -v systemctl'); adjust the rule if it differs."
  if [[ $install_sudoers -ne 1 || $non_interactive -eq 1 ]]; then
    [[ $install_sudoers -ne 1 ]] && echo "  (re-run with --install-sudoers to have this script write it, with confirmation)"
    return
  fi
  echo "  This will write exactly the line above to /etc/sudoers.d/${sudoers_name} on ${ORCH_HOST}"
  echo "  using the account's sudo password, validate it with visudo, and remove it if validation fails."
  if ! ask "Proceed?"; then warn "sudoers rule not installed"; return; fi
  local line; line="$(sudoers_line)"
  # -t: interactive sudo password prompt; the drop-in is validated before it is left in place.
  if ssh -t -i "$key_file" -p "$ORCH_SSH_PORT" -o IdentitiesOnly=yes -o UserKnownHostsFile="$known_hosts" -o StrictHostKeyChecking=yes \
      "${ORCH_SSH_USER}@${ORCH_HOST}" \
      "sudo sh -c 'f=/etc/sudoers.d/${sudoers_name}; printf \"%s\\n\" \"${line}\" > \$f && chmod 0440 \$f && visudo -cf \$f || { rm -f \$f; echo VISUDO_FAILED; exit 1; }'"; then
    sudo_authorized && ok "sudoers rule installed and verified" || warn "rule written but 'sudo -n -l' still fails — check for conflicting rules"
  else
    warn "sudoers rule not installed (see output above)"
  fi
}

# ---- 8. final test -----------------------------------------------------------
final_test() {
  step "End-to-end SSH check (no service restarted)"
  if ! key_auth_works; then err "key authentication FAILED for ${ORCH_SSH_USER}@${ORCH_HOST}"; return 1; fi
  ok "key authentication"
  set_ssh_opts
  local out
  if out="$(ssh "${ssh_opts[@]}" "$ssh_tgt" "sudo -n -l ${ORCH_RESTART_CMD}" 2>&1)"; then
    ok "sudo authorization: ${out}"
  else
    err "sudo authorization FAILED for the restart command: ${out:-not permitted by sudoers (or a password is required)}"; return 1
  fi
  if out="$(ssh "${ssh_opts[@]}" "$ssh_tgt" "sudo -n -l ${ORCH_NGINX_RELOAD_CMD}" 2>&1)"; then
    ok "sudo authorization: ${out}"
  else
    err "sudo authorization FAILED for the nginx reload command: ${out:-not permitted by sudoers (or a password is required)}"; return 1
  fi
}

# ---- main --------------------------------------------------------------------
cd "$here"
echo "${c_bold}orchestrator-acme-cert-manager — host setup${c_off}"
ensure_docker
ensure_dirs
ensure_key

if [[ -z "$ORCH_HOST" && $non_interactive -eq 0 ]]; then
  echo
  prompt_var ORCH_HOST "Orchestrator hostname (FQDN the certificate is for)"
  prompt_var ORCH_SSH_USER "SSH user on the Orchestrator" "$ORCH_SSH_USER"
  prompt_var ORCH_SSH_PORT "SSH port" "$ORCH_SSH_PORT"
  prompt_var ACME_EMAIL "ACME (Let's Encrypt) account email"
fi
[[ -n "$ORCH_DOMAIN" ]] || ORCH_DOMAIN="$ORCH_HOST"

ensure_env
remote_ok=1
if [[ -z "$ORCH_HOST" ]]; then
  warn "no Orchestrator host given — skipping config generation and remote steps (re-run with --host)"
  [[ -f "${cfg}/servers.json" ]] || { cp "${cfg}/servers.example.json" "${cfg}/servers.json"; chmod 600 "${cfg}/servers.json"; ok "copied config/servers.example.json → config/servers.json"; }
else
  validate_inputs
  ensure_servers_json
  if [[ $skip_remote -eq 1 ]]; then
    warn "--skip-remote: not contacting ${ORCH_HOST}. Manual steps:"
    echo "    ssh-keyscan -p ${ORCH_SSH_PORT} -t rsa,ecdsa,ed25519 ${ORCH_HOST} >> ${known_hosts}   # then verify the fingerprint"
    print_manual_key_install
    echo "    sudoers rule: $(sudoers_line)"
  else
    ensure_known_hosts
    ensure_authorized_key
    ensure_sudoers
    final_test || remote_ok=0
  fi
fi

step "Next steps"
cat <<EOF
  1. Put the Cloudflare DNS token and Orchestrator API key in .env (or per server in the web UI).
  2. Start:            docker compose up -d --build
  3. Preflight:        docker compose exec -T orchestrator-acme-cert-manager python -m app.cli check
  4. SSH test:         docker compose exec -T orchestrator-acme-cert-manager python -m app.cli ssh-test ${ORCH_SERVER_ID}
  5. Tunnel to the UI: ssh -L 8090:localhost:8090 <user>@<this-host>  →  http://localhost:8090
  6. Run a STAGING renewal first, confirm 'Activation: live', then switch the CA to production.
EOF
[[ $remote_ok -eq 1 ]] || warn "the SSH/sudo check did not pass — activation will fail until it does (see above)"

if [[ $start_stack -eq 1 ]]; then
  step "Starting the stack"
  if docker compose version >/dev/null 2>&1; then docker compose up -d --build
  else sudo_cmd docker compose up -d --build; fi
fi
