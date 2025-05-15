FROM scratch

ARG TARGETARCH
ARG GIT_VERSION
COPY ./bin/whisker-backend-${TARGETARCH} /whisker-backend

COPY ./bin/LICENSE /licenses/LICENSE

LABEL org.opencontainers.image.description="Whisker Backend is the backend service for the Whisker UI."
LABEL org.opencontainers.image.authors="maintainers@tigera.io"
LABEL org.opencontainers.image.source="https://github.com/projectcalico/calico"
LABEL org.opencontainers.image.title="Whisker Backend"
LABEL org.opencontainers.image.vendor="Project Calico"
LABEL org.opencontainers.image.version="${GIT_VERSION}"
LABEL org.opencontainers.image.licenses="Apache-2.0"

LABEL description="Whisker Backend is the backend service for the Whisker UI."
LABEL maintainer="maintainers@tigera.io"
LABEL name="Whisker Backend"
LABEL release=1
LABEL summary="Whisker Backend is the backend service for the Whisker UI."
LABEL vendor="Project Calico"
LABEL version="${GIT_VERSION}"

USER 10001:10001

CMD ["/whisker-backend"]
