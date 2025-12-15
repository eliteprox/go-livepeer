FROM nvidia/cuda:12.0.0-cudnn8-devel-ubuntu22.04

ARG GO_VERSION=1.25.0
# Match the host driver branch (570.124.06) to avoid NVML/decoder mismatches.
ARG NVIDIA_LIB_VERSION=570.124.06-0ubuntu1

ENV DEBIAN_FRONTEND=noninteractive \
    GO111MODULE=on \
    CGO_ENABLED=1 \
    GOPATH=/go \
    PKG_CONFIG_PATH="/usr/local/lib/pkgconfig"

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        git \
        build-essential \
        pkg-config \
        libx264-dev \
        libfdk-aac-dev \
        nasm \
        python3 \
        python3-venv \
        python3-pip \
        docker.io \
        libnvidia-compute-570=${NVIDIA_LIB_VERSION} \
        libnvidia-encode-570=${NVIDIA_LIB_VERSION} \
        libnvidia-decode-570=${NVIDIA_LIB_VERSION} \
        libnvidia-extra-570=${NVIDIA_LIB_VERSION} \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL "https://dl.google.com/go/go${GO_VERSION}.linux-amd64.tar.gz" \
    | tar -C /usr/local -xz \
    && mkdir -p /go/bin

ENV PATH="/usr/local/go/bin:/go/bin:${PATH}"

# Preinstall Go tools inside the image so debugging works out of the box
# With Go 1.25 we can pull latest gopls
RUN GOTOOLCHAIN="go${GO_VERSION}" \
    go install golang.org/x/tools/gopls@latest \
    && GOTOOLCHAIN="go${GO_VERSION}" \
    go install github.com/go-delve/delve/cmd/dlv@latest

WORKDIR /workspaces/go-livepeer

# Install ffmpeg via the existing helper script
COPY install_ffmpeg.sh /tmp/install_ffmpeg.sh
RUN chmod +x /tmp/install_ffmpeg.sh && /tmp/install_ffmpeg.sh

# Ensure libnvcuvid.so.1 is available for FFmpeg/NVDEC
RUN /bin/bash -lc 'set -euo pipefail; \
    if [ -f /usr/lib/x86_64-linux-gnu/libnvcuvid.so.570.124.06 ] && [ ! -f /usr/lib/x86_64-linux-gnu/libnvcuvid.so.1 ]; then \
        ln -s /usr/lib/x86_64-linux-gnu/libnvcuvid.so.570.124.06 /usr/lib/x86_64-linux-gnu/libnvcuvid.so.1; \
    fi'
