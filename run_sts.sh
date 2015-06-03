#!/bin/bash
./build_node.sh
docker save --output calico_containers/calico-node.tar calico/node
if [ -f busybox.tar ]; then
  docker pull busybox:latest
  docker save --output calico_containers/busybox.tar busybox:latest
fi

# Create the calicoctl binary here so it will be in the volume mounted on the hosts.
./create_binary.sh
nosetests calico_containers/tests/st --nocapture
