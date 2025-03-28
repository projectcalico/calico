FROM scratch

ARG TARGETARCH
COPY ./bin/whisker-backend-${TARGETARCH} /whisker-backend

USER 10001:10001

CMD ["/whisker-backend"]
