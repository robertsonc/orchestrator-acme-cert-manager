# syntax=docker/dockerfile:1
FROM python:3.12-slim

ARG LEGO_VERSION=5.3.1
ARG SUPERCRONIC_VERSION=0.2.33

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates openssh-client openssl tini \
    && rm -rf /var/lib/apt/lists/*

# Lego (ACME client)
RUN curl -fsSL "https://github.com/go-acme/lego/releases/download/v${LEGO_VERSION}/lego_v${LEGO_VERSION}_linux_amd64.tar.gz" \
        -o /tmp/lego.tar.gz \
    && tar -xzf /tmp/lego.tar.gz -C /usr/local/bin lego \
    && rm /tmp/lego.tar.gz

# supercronic (container-friendly cron)
RUN curl -fsSL "https://github.com/aptible/supercronic/releases/download/v${SUPERCRONIC_VERSION}/supercronic-linux-amd64" \
        -o /usr/local/bin/supercronic \
    && chmod +x /usr/local/bin/supercronic

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app/ ./app/
COPY config/crontab /app/crontab

ENV DATA_DIR=/data \
    PYTHONUNBUFFERED=1

EXPOSE 8080
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["/bin/sh", "/app/app/entrypoint.sh"]
