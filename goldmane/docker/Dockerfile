FROM scratch

ARG TARGETARCH
COPY ./bin/goldmane-${TARGETARCH} /goldmane

USER 10001:10001

CMD ["/goldmane"]
