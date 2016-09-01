FROM busybox

MAINTAINER Tom Denham <tom@tigera.io>

ADD dist/calico /opt/cni/bin/calico
ADD dist/calico-ipam /opt/cni/bin/calico-ipam
ADD k8s-install/scripts/install-cni.sh /install-cni.sh

ENV PATH=$PATH:/opt/cni/bin
VOLUME /opt/cni
WORKDIR /opt/cni/bin
CMD ["/opt/cni/bin/calico"]
