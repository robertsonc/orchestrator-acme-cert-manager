# syntax=docker/dockerfile:1
FROM python:3.12-slim

ARG LEGO_VERSION=5.5.2
ARG SUPERCRONIC_VERSION=0.2.33
# linux/amd64 or linux/arm64 (set by buildx; defaults to amd64 for a plain `docker build`)
ARG TARGETARCH=amd64
# The service user. docker-compose.yml overrides the uid/gid with OACM_UID/OACM_GID
# from .env (setup.sh writes your own ids there) so the bind mounts need no chown.
ARG APP_UID=10001
ARG APP_GID=10001

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates openssh-client openssl tini \
    && rm -rf /var/lib/apt/lists/*

# Lego (ACME client), verified against the release's checksum file
RUN set -eu; cd /tmp; \
    asset="lego_v${LEGO_VERSION}_linux_${TARGETARCH}.tar.gz"; \
    curl -fsSL "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/${asset}" -o "$asset"; \
    curl -fsSL "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_${LEGO_VERSION}_checksums.txt" -o lego_checksums.txt; \
    grep " ${asset}\$" lego_checksums.txt | sha256sum -c -; \
    tar -xzf "$asset" -C /usr/local/bin lego; \
    rm -f "$asset" lego_checksums.txt

# supercronic (container-friendly cron)
RUN curl -fsSL "https://github.com/aptible/supercronic/releases/download/v${SUPERCRONIC_VERSION}/supercronic-linux-${TARGETARCH}" \
        -o /usr/local/bin/supercronic \
    && chmod +x /usr/local/bin/supercronic

RUN groupadd -g "${APP_GID}" oacm && useradd -u "${APP_UID}" -g "${APP_GID}" -M -d /nonexistent -s /usr/sbin/nologin oacm

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY config/crontab /app/crontab
RUN mkdir -p /config /data/certs /data/logs /data/ssh /data/pki/certs \
    && chown -R oacm:oacm /config /data /app

ENV DATA_DIR=/data \
    CONFIG_DIR=/config \
    SERVERS_FILE=/config/servers.json \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOME=/tmp

LABEL org.opencontainers.image.source="https://github.com/robertsonc/orchestrator-acme-cert-manager" \
      org.opencontainers.image.description="Automated TLS certificate lifecycle for EdgeConnect Orchestrator and friends" \
      org.opencontainers.image.licenses="MIT"

USER oacm
EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/bin/sh", "/app/app/entrypoint.sh"]
