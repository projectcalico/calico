FROM busybox

LABEL maintainer "Tom Denham <tom@tigera.io>"

ADD dist/amd64/calico /opt/cni/bin/calico
ADD dist/amd64/flannel /opt/cni/bin/flannel
ADD dist/amd64/loopback /opt/cni/bin/loopback
ADD dist/amd64/host-local /opt/cni/bin/host-local
ADD dist/amd64/portmap /opt/cni/bin/portmap
ADD dist/amd64/tuning /opt/cni/bin/tuning
ADD dist/amd64/calico-ipam /opt/cni/bin/calico-ipam
ADD k8s-install/scripts/install-cni.sh /install-cni.sh
ADD k8s-install/scripts/calico.conf.default /calico.conf.tmp

ENV PATH=$PATH:/opt/cni/bin
WORKDIR /opt/cni/bin
CMD ["/opt/cni/bin/calico"]
