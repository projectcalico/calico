#!/bin/bash

set -x

# Automatically generate full mesh BIRD config for a multi-node
# Calico/DevStack deployment.

MY_ETCD_DIR=/calico-bird

# Arrange to kill the following sub-shell if the main script exits or
# dies in any way.
trap "kill -9 -- -$$" SIGINT SIGTERM EXIT

# In a sub-shell, periodically write our own IP into etcd.
(
    while true; do
	etcdctl set ${MY_ETCD_DIR}/$HOST_IP $HOST_IP --ttl 600
	sleep 300
    done
) &

# Generate the BIRD config, and regenerate whenever something changes
# in etcd under /calico-bird.
while true; do

    # First time through, or something has changed.  Get all the peer
    # IPs that are in etcd now.
    peer_ips=
    for key in `etcdctl ls ${MY_ETCD_DIR}`; do
	key=`basename $key`
	if [ $key != $HOST_IP ]; then
	    peer_ips="$peer_ips $key"
	fi
    done

    # Regenerate BIRD config, and restart BIRD.
    export TEMPLATE_DIR=/opt/stack/calico/etc/bird
    sudo -E /opt/stack/calico/etc/calico-gen-bird-mesh-conf.sh $HOST_IP 65411 $peer_ips

    # Wait for the next change.
    etcdctl watch ${MY_ETCD_DIR} --recursive

done
