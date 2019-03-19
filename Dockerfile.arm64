FROM arm64v8/debian:9.8-slim

LABEL maintainer "Casey Davenport <casey@tigera.io>"

ADD bin/arm64/ /opt/cni/bin/
ADD k8s-install/scripts/install-cni.sh /install-cni.sh
ADD k8s-install/scripts/calico.conf.default /calico.conf.tmp

ENV PATH=$PATH:/opt/cni/bin
WORKDIR /opt/cni/bin
CMD ["/opt/cni/bin/calico"]
