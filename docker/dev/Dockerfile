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
        uidmap \
        sudo \
        tcpdump \
        pkg-config \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/*

RUN groupadd --gid 1000 childflow \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash childflow \
    && usermod -aG sudo childflow \
    && printf 'childflow:100000:65536\n' >> /etc/subuid \
    && printf 'childflow:100000:65536\n' >> /etc/subgid \
    && printf 'childflow ALL=(ALL) NOPASSWD:ALL\n' >/etc/sudoers.d/childflow \
    && chmod 0440 /etc/sudoers.d/childflow

COPY --from=proxycheck-builder /out/proxycheck /usr/local/bin/proxycheck

WORKDIR /workspaces/childflow

ENV PATH=/usr/local/cargo/bin:${PATH}

USER childflow

CMD ["bash"]
