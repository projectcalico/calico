FROM busybox

MAINTAINER Tom Denham <tom@tigera.io>

ADD dist/calico /opt/cni/bin/calico
ADD dist/flannel /opt/cni/bin/flannel
ADD dist/loopback /opt/cni/bin/loopback
ADD dist/host-local /opt/cni/bin/host-local
ADD dist/calico-ipam /opt/cni/bin/calico-ipam
ADD k8s-install/scripts/install-cni.sh /install-cni.sh
ADD k8s-install/scripts/calico.conf.default /calico.conf.tmp

ENV PATH=$PATH:/opt/cni/bin
VOLUME /opt/cni
WORKDIR /opt/cni/bin
CMD ["/opt/cni/bin/calico"]
