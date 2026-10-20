#!/bin/bash
# =============================================================================
# One-time initialisation of the bundled lab CA (step-ca).
#
# Runs INSIDE the smallstep/step-ca image (bash + step available), invoked by
# setup.sh --with-ca with three mounts:
#   /home/step     ./data/pki        the ONLINE volume the lab-ca service runs from
#   /root-offline  ./data/pki-root   the OFFLINE root; never mounted into a service
#   /pki-init      ./pki (ro)        this script and the templates
#
# Online volume ($STEPPATH) after init:
#   certs/root_ca.crt            root certificate (public)
#   certs/intermediate_ca.crt    issuing CA with CRITICAL NAME CONSTRAINTS:
#                                names under LAB_CA_DOMAIN only, no IP SANs
#   secrets/intermediate_ca_key  the only private key online (encrypted)
#   secrets/password             its password
#   config/ca.json               ACME provisioner "$LAB_CA_PROVISIONER", DNS-01
#                                only, leaf template with a CRL distribution
#                                point; JWK provisioner "lab-admin" (same
#                                template) for manual ops; CRL with idpURL
#   config/lab-ca.meta           immutable identity (host/domain/port/...)
#                                checked on every re-run; mismatch fails closed
#   certs/root_ca.fingerprint    SHA-256 of the root, for out-of-band checks
#   certs/root-key-offline       marker: the root key was never written online
#
# Offline directory ($OFFLINE):
#   root_ca.crt, root_ca_key (encrypted), root_password
#   Generated here, used once to sign the intermediate, then left for the
#   operator to move off the host. The running CA never needs it.
# =============================================================================
set -euo pipefail

: "${STEPPATH:=/home/step}"
: "${OFFLINE:=${LAB_CA_OFFLINE_DIR:-/root-offline}}"
: "${LAB_CA_NAME:=Lab CA}"
: "${LAB_CA_HOST:?LAB_CA_HOST is required: the CA hostname, inside LAB_CA_DOMAIN}"
: "${LAB_CA_DOMAIN:?LAB_CA_DOMAIN is required: the DNS domain the CA may issue for}"
: "${LAB_CA_PORT:=9000}"
: "${LAB_CA_PROVISIONER:=lab}"
: "${LAB_CA_LEAF_MAX:=2160h}"      # 90 d, matches the renewal logic
TPL_DIR="${LAB_CA_TEMPLATE_DIR:-/pki-init}"
META="config/lab-ca.meta"
PROGRESS="config/.init-in-progress"   # exists only while a fresh init is running
CRL_URL="https://${LAB_CA_HOST}:${LAB_CA_PORT}/1.0/crl"

die() { echo "lab-ca-init: $*" >&2; exit "${2:-1}"; }

case "$LAB_CA_HOST" in
  *".${LAB_CA_DOMAIN}") ;;
  *) die "LAB_CA_HOST ($LAB_CA_HOST) must be a name under LAB_CA_DOMAIN ($LAB_CA_DOMAIN): the CA's own TLS certificate is issued by the name-constrained intermediate." 2 ;;
esac
[[ "$LAB_CA_PORT" =~ ^[0-9]+$ ]] || die "LAB_CA_PORT must be numeric" 2

mkdir -p "$STEPPATH"
cd "$STEPPATH"

# ---- re-run: verify identity, change nothing; resume an interrupted init ------
if [[ -f config/ca.json && ! -f "$META" && -f "$PROGRESS" ]]; then
  echo ">> a previous initialisation was interrupted ($(cat "$PROGRESS")); discarding the partial ONLINE state and starting over (the offline root in $OFFLINE is kept and reused)"
  rm -rf config db certs/intermediate_ca.crt certs/root_ca.crt certs/root_ca.fingerprint certs/root-key-offline secrets/intermediate_ca_key
fi
if [[ -f config/ca.json ]]; then
  if [[ ! -f "$META" ]]; then
    die "config/ca.json exists but $META is missing and no in-progress marker is present; this CA was not initialised by this script (or metadata was removed). Refusing to guess its identity." 3
  fi
  mismatch=0
  while IFS='=' read -r k v; do
    [[ -z "$k" || "$k" == \#* ]] && continue
    case "$k" in
      LAB_CA_HOST)        [[ "$v" == "$LAB_CA_HOST" ]]        || { echo "  stored LAB_CA_HOST=$v, requested $LAB_CA_HOST" >&2; mismatch=1; } ;;
      LAB_CA_DOMAIN)      [[ "$v" == "$LAB_CA_DOMAIN" ]]      || { echo "  stored LAB_CA_DOMAIN=$v, requested $LAB_CA_DOMAIN" >&2; mismatch=1; } ;;
      LAB_CA_PORT)        [[ "$v" == "$LAB_CA_PORT" ]]        || { echo "  stored LAB_CA_PORT=$v, requested $LAB_CA_PORT" >&2; mismatch=1; } ;;
      LAB_CA_PROVISIONER) [[ "$v" == "$LAB_CA_PROVISIONER" ]] || { echo "  stored LAB_CA_PROVISIONER=$v, requested $LAB_CA_PROVISIONER" >&2; mismatch=1; } ;;
      LAB_CA_NAME)        [[ "$v" == "$LAB_CA_NAME" ]]        || { echo "  stored LAB_CA_NAME=$v, requested $LAB_CA_NAME" >&2; mismatch=1; } ;;
    esac
  done < "$META"
  if [[ $mismatch -eq 1 ]]; then
    die "the persisted CA identity differs from the requested one (above). A CA cannot be renamed in place: to rebuild, stop the lab-ca service, move $STEPPATH aside (and $OFFLINE if you want a new root), re-run, and re-distribute the root." 3
  fi
  [[ -f secrets/root_ca_key ]] && die "secrets/root_ca_key is present in the ONLINE volume; move it to $OFFLINE (with its password) before continuing." 4
  echo "lab CA already initialised at $STEPPATH; identity verified against $META; nothing to do."
  exit 0
fi

# ---- fresh init ----------------------------------------------------------------
umask 077
mkdir -p secrets certs config config/templates
echo "started $(date -u +%Y-%m-%dT%H:%M:%SZ) for ${LAB_CA_HOST}:${LAB_CA_PORT}" > "$PROGRESS"
[[ -d "$OFFLINE" && -w "$OFFLINE" ]] || die "offline root directory $OFFLINE is missing or not writable" 2
[[ -s secrets/password ]] || head -c 30 /dev/urandom | base64 | tr -d '/+=' > secrets/password

if [[ -f "$OFFLINE/root_ca.crt" && -f "$OFFLINE/root_ca_key" && -s "$OFFLINE/root_password" ]]; then
  echo ">> reusing the existing offline root in $OFFLINE"
else
  echo ">> generating the root CA in $OFFLINE (its own password; never copied online)"
  head -c 30 /dev/urandom | base64 | tr -d '/+=' > "$OFFLINE/root_password"
  step certificate create "$LAB_CA_NAME Root CA" "$OFFLINE/root_ca.crt" "$OFFLINE/root_ca_key" \
    --profile root-ca --password-file "$OFFLINE/root_password" --not-after 87600h >/dev/null
fi

echo ">> step ca init ($LAB_CA_NAME, https://$LAB_CA_HOST:$LAB_CA_PORT) from the offline root"
step ca init --deployment-type standalone \
  --name "$LAB_CA_NAME" --dns "$LAB_CA_HOST" --address ":${LAB_CA_PORT}" \
  --provisioner lab-admin \
  --root "$OFFLINE/root_ca.crt" --key "$OFFLINE/root_ca_key" --key-password-file "$OFFLINE/root_password" \
  --password-file secrets/password --provisioner-password-file secrets/password \
  --acme >/dev/null
[[ "${LAB_CA_FAULT:-}" == "after-init" ]] && die "fault injected after step ca init (test hook)" 99

echo ">> re-issuing the intermediate with name constraints (permitted: .$LAB_CA_DOMAIN, no IPs)"
sed "s/__LAB_DOMAIN__/${LAB_CA_DOMAIN}/" "$TPL_DIR/intermediate.tpl" > config/templates/intermediate.tpl
step certificate create "$LAB_CA_NAME Intermediate CA" \
  certs/intermediate_ca.crt secrets/intermediate_ca_key \
  --template config/templates/intermediate.tpl \
  --ca certs/root_ca.crt --ca-key "$OFFLINE/root_ca_key" --ca-password-file "$OFFLINE/root_password" \
  --password-file secrets/password --not-after 43800h --force >/dev/null

echo ">> leaf template with CRL distribution point $CRL_URL"
sed "s#__CRL_URL__#${CRL_URL}#" "$TPL_DIR/leaf.tpl" > config/templates/leaf.tpl

echo ">> ACME provisioner '$LAB_CA_PROVISIONER' (DNS-01 only, leaf lifetime <= $LAB_CA_LEAF_MAX)"
step ca provisioner remove acme --ca-config config/ca.json >/dev/null 2>&1 || true
step ca provisioner add "$LAB_CA_PROVISIONER" --type ACME --challenge dns-01 \
  --x509-template config/templates/leaf.tpl \
  --x509-min-dur 24h --x509-max-dur "$LAB_CA_LEAF_MAX" --x509-default-dur "$LAB_CA_LEAF_MAX" \
  --ca-config config/ca.json >/dev/null
step ca provisioner update lab-admin --x509-template config/templates/leaf.tpl --ca-config config/ca.json >/dev/null

echo ">> enabling the CRL (issuing distribution point $CRL_URL)"
# step-ca writes pretty JSON whose first line is '{'; the image has no jq/python
# and its sed is BusyBox, so splice the stanza in with portable shell only.
[[ "$(head -n 1 config/ca.json)" == "{" ]] || die "config/ca.json does not start with '{' as expected; refusing to patch it" 5
{
  echo "{"
  echo "  \"crl\": {\"enabled\": true, \"generateOnRevoke\": true, \"cacheDuration\": \"24h\", \"idpURL\": \"${CRL_URL}\"},"
  tail -n +2 config/ca.json
} > config/ca.json.new
mv config/ca.json.new config/ca.json
grep -q "\"idpURL\": \"${CRL_URL}\"" config/ca.json || die "CRL stanza was not written to config/ca.json" 5

step certificate fingerprint certs/root_ca.crt > certs/root_ca.fingerprint
chmod 644 certs/root_ca.crt certs/intermediate_ca.crt certs/root_ca.fingerprint
cat > "$META" <<EOF
# identity of this lab CA; checked on every setup re-run, do not edit
LAB_CA_NAME=${LAB_CA_NAME}
LAB_CA_HOST=${LAB_CA_HOST}
LAB_CA_DOMAIN=${LAB_CA_DOMAIN}
LAB_CA_PORT=${LAB_CA_PORT}
LAB_CA_PROVISIONER=${LAB_CA_PROVISIONER}
LAB_CA_INITIALISED=$(date -u +%Y-%m-%dT%H:%M:%SZ)
EOF
chmod 644 "$META"
rm -f "$PROGRESS"

[[ -f secrets/root_ca_key ]] && die "unexpected: root key found in the online volume" 4
echo "root key generated in $OFFLINE on $(date -u +%Y-%m-%dT%H:%M:%SZ); never present in this volume" > certs/root-key-offline
chmod 644 certs/root-key-offline

cat <<EOF

Lab CA initialised.
  Root fingerprint (SHA-256): $(cat certs/root_ca.fingerprint)
  ACME directory:             https://${LAB_CA_HOST}:${LAB_CA_PORT}/acme/${LAB_CA_PROVISIONER}/directory
  Root download:              https://${LAB_CA_HOST}:${LAB_CA_PORT}/roots.pem
  CRL (also in every leaf):   ${CRL_URL}
  Issuing scope:              *.${LAB_CA_DOMAIN} only (name constraints, critical)
  Online private key:         secrets/intermediate_ca_key only
  Offline root material:      ${OFFLINE} (root_ca_key + root_password) — move it off this host
EOF
