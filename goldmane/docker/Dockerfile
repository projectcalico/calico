FROM scratch

ARG TARGETARCH
COPY ./bin/goldmane-${TARGETARCH} /goldmane
COPY ./bin/health-${TARGETARCH} /health

USER 10001:10001

CMD ["/goldmane"]
