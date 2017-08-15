FROM busybox

MAINTAINER Gunjan Patel <gunjan@tigera.io>

ADD dist/calicoctl-v1.4 /sbin/calicoctl-v1.4
ADD dist/calicoctl-v1.5 /sbin/calicoctl-v1.5
ADD dist/kubectl /sbin/kubectl

ADD script/upgrade.sh /upgrade.sh
ADD manifests/crds.yaml /crds.yaml

WORKDIR /

CMD ["/upgrade.sh"]