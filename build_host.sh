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

#### TEMP CODE ####
# if there's a customized docker binary in the current directory, run it in
# the docker dir.
if [ -e docker-dev ]; then
  # Make sure the existing docker daemon is stopped and run the new one (if
  # it's not already running)
  docker exec calico-host pkill docker
  docker exec -d calico-host bash -c 'pgrep docker-dev || /code/docker-dev -dD'
  docker exec calico-host ln -s /code/docker-dev /usr/local/bin/docker
fi

