FROM golang:1.25-bookworm AS proxycheck-builder

WORKDIR /src
COPY docker/dev/proxycheck/go.mod docker/dev/proxycheck/main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/proxycheck .

FROM golang:1.25-bookworm AS vhs-builder

RUN go install github.com/charmbracelet/vhs@latest

FROM debian:trixie-slim AS ttyd-fetch

ARG TTYD_VERSION=1.7.7
ARG TARGETARCH

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN case "${TARGETARCH}" in \
        "arm64") asset="ttyd.aarch64" ;; \
        "amd64") asset="ttyd.x86_64" ;; \
        "386") asset="ttyd.i686" ;; \
        "arm") asset="ttyd.armhf" ;; \
        *) echo "unsupported TARGETARCH for ttyd: ${TARGETARCH}" >&2; exit 1 ;; \
    esac \
    && curl -fsSL "https://github.com/tsl0922/ttyd/releases/download/${TTYD_VERSION}/${asset}" -o /usr/local/bin/ttyd \
    && chmod +x /usr/local/bin/ttyd

FROM rust:1-trixie

RUN rustup component add clippy

RUN apt-get clean \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives/* \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        busybox-static \
        chromium \
        iproute2 \
        iputils-ping \
        iptables \
        libcap2-bin \
        uidmap \
        sudo \
        tcpdump \
        traceroute \
        ffmpeg \
        pkg-config \
    && setcap cap_net_raw=ep /usr/bin/ping \
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
COPY --from=vhs-builder /go/bin/vhs /usr/local/bin/vhs
COPY --from=ttyd-fetch /usr/local/bin/ttyd /usr/local/bin/ttyd

WORKDIR /workspaces/childflow

ENV PATH=/usr/local/cargo/bin:${PATH}
ENV CHROME_PATH=/usr/bin/chromium

USER childflow

CMD ["bash"]
