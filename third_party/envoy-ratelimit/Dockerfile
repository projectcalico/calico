# Copyright (c) 2024-2025 Tigera, Inc. All rights reserved.

ARG CALICO_BASE

FROM ${CALICO_BASE}

ARG TARGETARCH

COPY bin/envoy-ratelimit-${TARGETARCH} /bin/ratelimit
