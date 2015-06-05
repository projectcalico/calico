#!/usr/bin/env bash
CONTAINER_NAME=build-calico-host
# This script creates an image called calico/host that the STs can use for
# running tests.
# It builds the image by running a container called $CONTAINER_NAME and
# leaves it running. This allows the calico/host image to be incrementally
# updated when code changes.

# If there's a $CONTAINER_NAME container running already, then assume we don't
# need to build another.
if ! docker ps | grep -w $CONTAINER_NAME; then
  # Start docker in docker, mapping the calico-docker code into it.
  docker run -v `pwd`:/code --privileged -tid --name $CONTAINER_NAME jpetazzo/dind
  # Pre-cache the busybox image
  docker exec $CONTAINER_NAME docker pull busybox
fi

# Always refesh the calico/node image in the container by running build_node.sh
docker exec $CONTAINER_NAME bash -c 'cd /code && ./build_node.sh'

#### TEMP CODE ####
# if there's a customized docker binary in the current directory, run it in
# the $CONTAINER_NAME container, replacing the "normal" docker container.
if [ -e docker-dev ]; then
  # Make sure the existing docker daemon is stopped and run the new one (if
  # it's not already running)
  docker exec $CONTAINER_NAME pkill docker
  docker exec -d $CONTAINER_NAME bash -c 'pgrep docker-dev || /code/docker-dev -dD'
  docker exec $CONTAINER_NAME ln -sf /code/docker-dev /usr/local/bin/docker
fi

# The tests expect to be able to run a host based on an image called
# calico/host. So always commit the latest image with that name.
docker commit $CONTAINER_NAME calico/host