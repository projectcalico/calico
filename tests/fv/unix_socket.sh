#!/bin/sh
set -e
set -x

dist/calicoctl restart-docker-without-alternative-unix-socket

# Set it up
docker rm -f etcd || true
docker run --restart=always -d --net=host --name etcd quay.io/coreos/etcd:v2.0.10

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
dist/calicoctl restart-docker-with-alternative-unix-socket
# etcd is running under docker, so wait for it to come up.
sleep 5
dist/calicoctl node --ip=127.0.0.1 
docker ps

# Switch back to without the unix socket and check that everything still works.
dist/calicoctl restart-docker-without-alternative-unix-socket
# etcd is running under docker, so wait for it to come up.
sleep 5
dist/calicoctl node --ip=127.0.0.1
docker ps
while ! DOCKER_HOST=localhost:2377 docker ps; do
echo "Waiting for powerstrip to come up"
  sleep 1
done

echo "Tests completed successfully"
