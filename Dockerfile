FROM alpine:3.4

MAINTAINER Tom Denham <tom@tigera.io>

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:/opt/cni/bin:$PATH
RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"
RUN mkdir -p /opt/cni/bin
ARG CALICO_CNI_VERSION
ENV CALICO_CNI_VERSION ${CALICO_CNI_VERSION}

# Add source files.
ADD glide.yaml glide.lock Makefile /go/src/github.com/projectcalico/calico-cni/
ADD *.go /go/src/github.com/projectcalico/calico-cni/
ADD utils /go/src/github.com/projectcalico/calico-cni/utils
ADD ipam /go/src/github.com/projectcalico/calico-cni/ipam
ADD k8s /go/src/github.com/projectcalico/calico-cni/k8s

# Add CNI install script.
ADD ./k8s-install/scripts/install-cni.sh /install-cni.sh

RUN set -ex \
	&& apk add --no-cache --virtual .build-deps \
		bash \
		gcc \
		musl-dev \
		openssl \
		go \
		ca-certificates \
		git \
		make \
    && go get -u github.com/Masterminds/glide \
    && cd /go/src/github.com/projectcalico/calico-cni \
    && make binary CALICO_CNI_VERSION=$CALICO_CNI_VERSION \
    && mv dist/calico* /opt/cni/bin \
	&& rm -rf /go /root/.glide \
	&& apk del .build-deps

VOLUME /opt/cni
WORKDIR /opt/cni/bin
