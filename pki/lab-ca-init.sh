#!/bin/bash
# =============================================================================
# One-time initialisation of the bundled lab CA (step-ca).
#
# Runs INSIDE the smallstep/step-ca image (bash + step available), invoked by
# setup.sh --with-ca as:
#   docker run --rm --entrypoint bash -v ./data/pki:/home/step -v ./pki:/pki-init:ro ... /pki-init/lab-ca-init.sh
#
# Produces, under $STEPPATH (/home/step == ./data/pki on the host):
#   certs/root_ca.crt            offline-style root (10 y), key encrypted at rest
#   certs/intermediate_ca.crt    online issuing CA (5 y) with CRITICAL NAME
#                                CONSTRAINTS: only names under LAB_CA_DOMAIN,
#                                no IP SANs. A leaked issuing key cannot forge
#                                certificates for names outside the lab.
#   config/ca.json               ACME provisioner "$LAB_CA_PROVISIONER" with
#                                DNS-01 as the only challenge; CRL enabled;
#                                JWK provisioner "lab-admin" for manual ops.
#   secrets/password             password protecting both CA keys (0600)
#   certs/root_ca.fingerprint    SHA-256 of the root, for out-of-band checks
#
# Idempotent: exits 0 without changes when config/ca.json already exists.
# =============================================================================
set -euo pipefail

: "${STEPPATH:=/home/step}"
: "${LAB_CA_NAME:=Lab CA}"
: "${LAB_CA_HOST:?LAB_CA_HOST is required: the CA hostname, inside LAB_CA_DOMAIN}"
: "${LAB_CA_DOMAIN:?LAB_CA_DOMAIN is required (DNS domain the CA may issue for)}"
: "${LAB_CA_PROVISIONER:=lab}"
: "${LAB_CA_LEAF_MAX:=2160h}"      # 90 d, matches the renewal logic
TEMPLATE="${LAB_CA_TEMPLATE:-/pki-init/intermediate.tpl}"

case "$LAB_CA_HOST" in
  *".${LAB_CA_DOMAIN}") ;;
  *) echo "LAB_CA_HOST ($LAB_CA_HOST) must be a name under LAB_CA_DOMAIN ($LAB_CA_DOMAIN):" >&2
     echo "the CA's own TLS certificate is issued by the name-constrained intermediate." >&2; exit 2 ;;
esac

mkdir -p "$STEPPATH"
cd "$STEPPATH"
if [[ -f config/ca.json ]]; then
  echo "lab CA already initialised at $STEPPATH (config/ca.json exists); nothing to do."
  exit 0
fi

umask 077
mkdir -p secrets certs config
if [[ ! -s secrets/password ]]; then
  head -c 30 /dev/urandom | base64 | tr -d '/+=' > secrets/password
fi

echo ">> step ca init ($LAB_CA_NAME, https://$LAB_CA_HOST:9000)"
step ca init --deployment-type standalone \
  --name "$LAB_CA_NAME" --dns "$LAB_CA_HOST" --address ":9000" \
  --provisioner lab-admin \
  --password-file secrets/password --provisioner-password-file secrets/password \
  --acme >/dev/null

echo ">> re-issuing the intermediate with name constraints (permitted: .$LAB_CA_DOMAIN, no IPs)"
sed "s/__LAB_DOMAIN__/${LAB_CA_DOMAIN}/" "$TEMPLATE" > /tmp/intermediate.tpl
step certificate create "$LAB_CA_NAME Intermediate CA" \
  certs/intermediate_ca.crt secrets/intermediate_ca_key \
  --template /tmp/intermediate.tpl \
  --ca certs/root_ca.crt --ca-key secrets/root_ca_key --ca-password-file secrets/password \
  --password-file secrets/password --not-after 43800h --force >/dev/null
rm -f /tmp/intermediate.tpl

echo ">> ACME provisioner '$LAB_CA_PROVISIONER' (DNS-01 only, leaf lifetime <= $LAB_CA_LEAF_MAX)"
step ca provisioner remove acme --ca-config config/ca.json >/dev/null 2>&1 || true
step ca provisioner add "$LAB_CA_PROVISIONER" --type ACME --challenge dns-01 \
  --x509-min-dur 24h --x509-max-dur "$LAB_CA_LEAF_MAX" --x509-default-dur "$LAB_CA_LEAF_MAX" \
  --ca-config config/ca.json >/dev/null

echo ">> enabling the CRL"
# step-ca writes pretty JSON whose first line is '{'; the image has no jq/python.
sed -i '0,/^{$/s/^{$/{\n  "crl": {"enabled": true, "generateOnRevoke": true, "cacheDuration": "24h"},/' config/ca.json

step certificate fingerprint certs/root_ca.crt > certs/root_ca.fingerprint
chmod 644 certs/root_ca.crt certs/intermediate_ca.crt certs/root_ca.fingerprint

cat <<EOF

Lab CA initialised.
  Root fingerprint (SHA-256): $(cat certs/root_ca.fingerprint)
  ACME directory:             https://${LAB_CA_HOST}:9000/acme/${LAB_CA_PROVISIONER}/directory
  Root download:              https://${LAB_CA_HOST}:9000/roots.pem
  CRL:                        https://${LAB_CA_HOST}:9000/1.0/crl
  Issuing scope:              *.${LAB_CA_DOMAIN} only (name constraints, critical)
EOF
