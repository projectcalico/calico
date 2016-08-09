FROM golang:1.6-alpine

MAINTAINER Tom Denham <tom@tigera.io>

RUN apk -U add bash git iproute2 curl make
RUN apk add --update-cache --repository http://dl-cdn.alpinelinux.org/alpine/edge/testing etcd

RUN go get github.com/onsi/ginkgo/ginkgo
WORKDIR /go/src/github.com/projectcalico/calico-cni