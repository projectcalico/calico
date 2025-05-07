ARG CALICO_BASE
FROM ${CALICO_BASE}
ARG TARGETARCH
COPY bin/envoy-ratelimit-${TARGETARCH} /bin/ratelimit

# These labels are required for OCP Certification
LABEL description="Envoy Ratelimit is WHATEVER ENVOY RATELIMIT DOES"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Envoy Ratelimit"
LABEL release="1"
LABEL summary="Envoy Ratelimit is THE SAME EXPLANATION AS THE DESCRIPTION"
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"
