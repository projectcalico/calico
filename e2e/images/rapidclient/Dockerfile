FROM scratch

# TARGETARCH is set by buildx per target platform; it selects the matching
# pre-built static binary (bin/rapidclient-<arch>) so a single Dockerfile
# produces a multi-arch manifest.
ARG TARGETARCH

COPY bin/rapidclient-${TARGETARCH} /rapidclient

ENTRYPOINT ["/rapidclient"]
