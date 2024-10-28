FROM scratch AS source

ARG BIN_DIR
ARG TARGETARCH

COPY LICENSE /licenses/LICENSE

COPY ${BIN_DIR}/apiserver-${TARGETARCH} /code/apiserver

FROM calico/base

ARG GIT_VERSION=unknown

LABEL description="Aggregated API server which enables calico resources to be managed via kubectl"
LABEL maintainer="maintainers@tigera.io"
LABEL name="Calico API server"
LABEL release="1"
LABEL summary="Calico API server"
LABEL vendor="Project Calico"
LABEL version=${GIT_VERSION}

COPY --from=source / /

USER 10001:10001

WORKDIR /code

ENTRYPOINT ["/code/apiserver"]
