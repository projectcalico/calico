FROM scratch as source

ARG BIN_DIR
ARG TARGETARCH

COPY ${BIN_DIR}/apiserver-${TARGETARCH} /code/apiserver
COPY ${BIN_DIR}/filecheck-${TARGETARCH} /code/filecheck

FROM calico/base

COPY --from=source / /

USER 10001:10001

WORKDIR /code

ENTRYPOINT ["/code/apiserver"]
