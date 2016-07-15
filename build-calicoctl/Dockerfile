FROM centos:6.6

# gcc for cgo
RUN yum install -y \
		g++ \
		gcc \
		libc6-dev \
		make \
		curl \
		tar \
		git \
		wget

# Install newer version of git, default version on Centos 6.6 hangs under
# go get.
RUN wget http://pkgs.repoforge.org/rpmforge-release/rpmforge-release-0.5.3-1.el6.rf.x86_64.rpm && \
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

RUN go get "github.com/Masterminds/glide"


