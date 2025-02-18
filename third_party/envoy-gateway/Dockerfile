# This is a copy of
# https://github.com/envoyproxy/gateway/blob/v1.1.2/tools/docker/envoy-gateway/Dockerfile
# but:
# - using calico/base instead of distroless
# - using TARGETARCH instead of TARGETPLATFORM.

FROM --platform=linux/amd64 busybox AS source
# Create the data directory for eg
RUN mkdir -p /var/lib/eg

FROM calico/base:latest-${TARGETARCH}
ARG TARGETARCH
COPY bin/envoy-gateway-${TARGETARCH} /usr/local/bin/envoy-gateway
COPY --from=source --chown=65532:65532 /var/lib /var/lib

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/envoy-gateway"]
ENV PATH="$PATH:/usr/local/bin"
