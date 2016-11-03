FROM golang:1.7

MAINTAINER Shaun Crampton <shaun@tigera.io>

# Install build pre-reqs:
# - bsdmainutils contains the "column" command, used to format the coverage
#   data.
RUN apt-get update && \
    apt-get install -y bsdmainutils && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN go get github.com/Masterminds/glide \
           github.com/onsi/ginkgo/ginkgo \
           github.com/onsi/gomega \
           github.com/wadey/gocovmerge

# glide requires the current user to exist inside the container, copy in
# some user/group entries calculated by the makefile.
ADD passwd /passwd
RUN cat /passwd >> /etc/passwd
ADD group /group
RUN cat /group >> /etc/group

# Make sure the normal user has write access to the GOPATH.  Needs to be done
# at the end because the above commands will write into this directory as root.
RUN chmod -R a+wX $GOPATH /usr/local/go

# Disable cgo so that binaries we build will be fully static.
ENV CGO_ENABLED=0

WORKDIR /go/src/github.com/projectcalico/felix
