FROM rust:1-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iproute2 \
        iptables \
        tcpdump \
        ca-certificates \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /workspaces/childflow

CMD ["bash"]
