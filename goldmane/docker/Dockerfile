FROM scratch

ARG TARGETARCH
ARG GIT_VERSION
COPY ./bin/goldmane-${TARGETARCH} /goldmane
COPY ./bin/health-${TARGETARCH} /health

COPY ./bin/LICENSE /licenses/LICENSE

LABEL org.opencontainers.image.description="Goldmane is a flow aggregation service."
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="Goldmane"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

LABEL description="Goldmane is a flow aggregation service."
LABEL maintainer="maintainers@tigera.io"
LABEL name="Goldmane"
LABEL release=1
LABEL summary="Goldmane is a flow aggregation service."
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

USER 10001:10001

CMD ["/goldmane"]
