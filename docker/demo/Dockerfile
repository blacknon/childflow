FROM python:3.12-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /demo

COPY docker/demo/create-self-signed-cert.sh /demo/create-self-signed-cert.sh
COPY docker/demo/origin_server.py /demo/origin_server.py
COPY docker/demo/proxy_server.py /demo/proxy_server.py

RUN chmod +x /demo/create-self-signed-cert.sh
