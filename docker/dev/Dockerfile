FROM golang:1.25-bookworm AS proxycheck-builder

WORKDIR /src
COPY docker/dev/proxycheck/go.mod docker/dev/proxycheck/main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/proxycheck .

FROM rust:1-trixie

RUN rustup component add clippy

RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        busybox-static \
        iproute2 \
        iptables \
        tcpdump \
        pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

COPY --from=proxycheck-builder /out/proxycheck /usr/local/bin/proxycheck

WORKDIR /workspaces/childflow

CMD ["bash"]
