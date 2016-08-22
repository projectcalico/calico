FROM scratch

MAINTAINER Tom Denham <tom@tigera.io>

ADD dist/calico /opt/cni/bin/calico
ADD dist/calico-ipam /opt/cni/bin/calico-ipam
ENV PATH=$PATH:/opt/cni/bin
VOLUME /opt/cni
WORKDIR /opt/cni/bin
CMD ["/opt/cni/bin/calico"]
