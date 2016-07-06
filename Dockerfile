FROM debian:jessie
MAINTAINER projectcalico

RUN mkdir -p /opt/cni/bin
ADD ./dist/calico /opt/cni/bin
ADD ./dist/calico-ipam /opt/cni/bin
VOLUME /opt/cni
ENV PATH=$PATH:/opt/cni/bin
WORKDIR /opt/cni/bin
