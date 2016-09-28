FROM alpine:3.4
MAINTAINER Tom Denham <tom@projectcalico.org>

# Download and install glibc in one layer
RUN apk --no-cache add wget ca-certificates libgcc && \
    wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://raw.githubusercontent.com/sgerrand/alpine-pkg-glibc/master/sgerrand.rsa.pub && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.23-r3/glibc-2.23-r3.apk && \
    wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.23-r3/glibc-bin-2.23-r3.apk && \
    apk add glibc-2.23-r3.apk glibc-bin-2.23-r3.apk && \
    /usr/glibc-compat/sbin/ldconfig /lib /usr/glibc/usr/lib && \
    apk del wget ca-certificates && \
    rm -f glibc-2.23-r3.apk glibc-bin-2.23-r3.apk

RUN apk --no-cache add ip6tables ipset iputils iproute2 conntrack-tools 

ADD dist/calico-felix /code
WORKDIR /code

# Minimal dummy config
RUN mkdir /etc/calico && echo -e "[global]\nMetadataAddr = None\nLogFilePath = None\nLogSeverityFile = None" >/etc/calico/felix.cfg

# Run felix by default
CMD ["./calico-felix"]
