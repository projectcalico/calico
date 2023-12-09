FROM scratch as source

ARG BIN_DIR
ARG TARGETARCH

COPY ${BIN_DIR}/apiserver-${TARGETARCH} /code/apiserver
COPY ${BIN_DIR}/filecheck-${TARGETARCH} /code/filecheck

FROM jha48/base

COPY --from=source / /

USER 999

ENTRYPOINT ["/code/apiserver"]
