FROM arm64v8/alpine:3.8
MAINTAINER Tom Denham <tom@projectcalico.org>

ADD bin/calicoctl-linux-arm64 /calicoctl

ENV CALICO_CTL_CONTAINER=TRUE
ENV PATH=$PATH:/

WORKDIR /root
ENTRYPOINT ["/calicoctl"]
