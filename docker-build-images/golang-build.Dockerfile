# Centos 6.6 has the oldest version of glibc that we support.  Build against
# that.
FROM centos:6.6

MAINTAINER Shaun Crampton <shaun@tigera.io>

# gcc for cgo
RUN yum install -y \
		g++ \
		gcc \
		libc6-dev \
		make \
		curl \
		tar \
		wget

# Install newer version of git, default version on Centos 6.6 hangs under
# go get.
RUN wget http://repository.it4i.cz/mirrors/repoforge/redhat/el6/en/x86_64/rpmforge/RPMS/rpmforge-release-0.5.3-1.el6.rf.x86_64.rpm && \
    yum install -y rpmforge-release-0.5.3-1.el6.rf.x86_64.rpm && \
    yum install -y --enablerepo=rpmforge-extras git

ENV GOLANG_VERSION 1.6.2
ENV GOLANG_DOWNLOAD_URL https://golang.org/dl/go$GOLANG_VERSION.linux-amd64.tar.gz
ENV GOLANG_DOWNLOAD_SHA256 e40c36ae71756198478624ed1bb4ce17597b3c19d243f3f0899bb5740d56212a

RUN curl -fsSL "$GOLANG_DOWNLOAD_URL" -o golang.tar.gz \
	&& echo "$GOLANG_DOWNLOAD_SHA256  golang.tar.gz" | sha256sum -c - \
	&& tar -C /usr/local -xzf golang.tar.gz \
	&& rm golang.tar.gz

ENV GOPATH /go
ENV PATH $GOPATH/bin:/usr/local/go/bin:$PATH

RUN mkdir -p "$GOPATH/src" "$GOPATH/bin" && chmod -R 777 "$GOPATH"

# glide requires the current user to exist inside the container, copy in
# some user/group entries calculated by the makefile.
ADD passwd /passwd
RUN cat /passwd >> /etc/passwd
ADD group /group
RUN cat /group >> /etc/group

RUN go get github.com/Masterminds/glide
RUN go get github.com/onsi/ginkgo/ginkgo
RUN go get github.com/onsi/gomega
RUN go get github.com/wadey/gocovmerge

RUN chmod -R a+w /go

WORKDIR /go/src/github.com/projectcalico/felix
