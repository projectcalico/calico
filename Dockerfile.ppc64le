FROM scratch

LABEL maintainer "maintainers@projectcalico.org"

ADD licenses/ /licenses
ADD LICENSE /licenses/

ADD bin/ppc64le /opt/cni/bin/

ENV PATH=$PATH:/opt/cni/bin
WORKDIR /opt/cni/bin
CMD ["/opt/cni/bin/install"]