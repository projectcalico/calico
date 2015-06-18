#!/bin/sh
# Copyright 2015 Metaswitch Networks
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
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
