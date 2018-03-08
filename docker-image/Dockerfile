FROM alpine:3.7
MAINTAINER Shaun Crampton <shaun@tigera.io>

# Since our binary isn't designed to run as PID 1, run it via the tini init daemon.
RUN apk --no-cache add --update tini
ENTRYPOINT ["/sbin/tini", "--"]

# Download and install glibc in one layer
RUN apk --no-cache add wget ca-certificates libgcc && \
    wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://raw.githubusercontent.com/sgerrand/alpine-pkg-glibc/master/sgerrand.rsa.pub && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.23-r3/glibc-2.23-r3.apk && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.23-r3/glibc-bin-2.23-r3.apk && \
    apk add glibc-2.23-r3.apk glibc-bin-2.23-r3.apk && \
    /usr/glibc-compat/sbin/ldconfig /lib /usr/glibc/usr/lib && \
    apk del wget && \
    rm -f glibc-2.23-r3.apk glibc-bin-2.23-r3.apk

# Install Felix's dependencies.
RUN apk --no-cache add ip6tables ipset iputils iproute2 conntrack-tools

ADD felix.cfg /etc/calico/felix.cfg
ADD calico-felix-wrapper usr/bin

# Put out binary in /code rather than directly in /usr/bin.  This allows the downstream builds
# to more easily extract the Felix build artefacts from the container.
RUN mkdir /code
ADD bin/calico-felix /code
WORKDIR /code
RUN ln -s /code/calico-felix /usr/bin
RUN mkdir -p /var/run/calico

# Run felix by default
CMD ["calico-felix-wrapper"]
