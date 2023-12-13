FROM scratch as source

ARG BIN_DIR
ARG TARGETARCH

COPY LICENSE /licenses/LICENSE

COPY ${BIN_DIR}/apiserver-${TARGETARCH} /code/apiserver
COPY ${BIN_DIR}/filecheck-${TARGETARCH} /code/filecheck

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

WORKDIR /code

ENTRYPOINT ["/code/apiserver"]
