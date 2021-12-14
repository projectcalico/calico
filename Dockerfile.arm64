FROM scratch

ADD licenses/ /licenses
ADD LICENSE /licenses/

LABEL maintainer "maintainers@projectcalico.org"

ADD bin/arm64 /opt/cni/bin/

ENV PATH=$PATH:/opt/cni/bin
WORKDIR /opt/cni/bin
CMD ["/opt/cni/bin/install"]