#!/usr/bin/env bash
# If there's a calico-host container running already, then assume we don't
# need to build another.
if ! docker ps | grep -w calico-host; then
  docker run -v `pwd`:/code --privileged -tid --name calico-host jpetazzo/dind
  docker exec calico-host docker pull busybox
fi

# The tests expect to be able to run a host based on an image called
# calico/host. SO always commit the latest image with that name.
docker exec calico-host bash -c 'cd /code && ./build_node.sh'
docker commit calico-host calico/host
