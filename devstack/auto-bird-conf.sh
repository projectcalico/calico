#!/bin/bash

set -x

# Automatically generate full mesh BIRD config for a multi-node
# Calico/DevStack deployment.

MY_ETCD_DIR=/calico-bird

# Arrange to kill the following sub-shell if the main script exits or
# dies in any way.
trap "kill -9 -- -$$" SIGINT SIGTERM EXIT

# Determine our global IPv6 address.
set - `ip -6 a | awk '/inet6 .* global/ {print $2;}' | cut -d/ -f1`
HOST_IPV6=$1

# In a sub-shell, periodically write our own IP into etcd.
(
    while true; do
        etcdctl set ${MY_ETCD_DIR}/$HOST_IP $HOST_IP --ttl 600
        if test -n "$HOST_IPV6"; then
            etcdctl set ${MY_ETCD_DIR}/$HOST_IPV6 $HOST_IPV6 --ttl 600
        fi
        sleep 300
    done
) &

# Generate the BIRD config, and regenerate whenever something changes
# in etcd under /calico-bird.
while true; do

    # First time through, or something has changed.  Get all the peer
    # IPs that are in etcd now.
    peer_ips=
    peer_ipv6s=
    for key in `etcdctl ls ${MY_ETCD_DIR}`; do
        key=`basename $key`
        case $key in
            *:* )
                # IPv6
                if [ $key != "$HOST_IPV6" ]; then
                    peer_ipv6s="$peer_ipv6s $key"
                fi
                ;;

            *)
                # IPv4
                if [ $key != $HOST_IP ]; then
                    peer_ips="$peer_ips $key"
                fi
                ;;
        esac
    done

    # Regenerate BIRD config, and restart BIRD.
    export TEMPLATE_DIR=/opt/stack/felix/etc/bird
    sudo -n -E /opt/stack/felix/etc/calico-gen-bird-mesh-conf.sh $HOST_IP 65411 $peer_ips
    if test -n "$HOST_IPV6"; then
        sudo -n -E /opt/stack/felix/etc/calico-gen-bird6-mesh-conf.sh $HOST_IP $HOST_IPV6 65411 $peer_ipv6s
    fi

    # Wait for the next change.
    etcdctl watch ${MY_ETCD_DIR} --recursive

done
