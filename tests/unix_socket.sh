#!/bin/sh
set -e
set -x

# Set it up
docker rm -f etcd || true
docker run --restart=always -d -p 4001:4001 --name etcd quay.io/coreos/etcd:v0.4.6

# Run without the unix socket. Check that docker can be accessed though both
# the unix socket and the powerstrip TCP port.
dist/calicoctl node --ip=127.0.0.1
docker ps
while ! DOCKER_HOST=localhost:2377 docker ps; do
echo "Waiting for powerstrip to come up"
  sleep 1
done


# Run with the unix socket. Check that docker can be access through both
# unix sockets.
dist/calicoctl node --ip=127.0.0.1 --force-unix-socket
docker ps

# Switch back to without the unix socket and check that everything still works.
dist/calicoctl node --ip=127.0.0.1
docker ps
while ! DOCKER_HOST=localhost:2377 docker ps; do
echo "Waiting for powerstrip to come up"
  sleep 1
done