#!/bin/bash

set -x
set -e
date
pwd
git status

# We *must* remove all inner containers and images before removing the outer
# container. Otherwise the inner images will stick around and fill disk.
# https://github.com/jpetazzo/dind#important-warning-about-disk-usage
docker exec -t host1 bash -c 'docker rm -f $(docker ps -qa) ; \
                              docker rmi $(docker images -qa)' || true
docker rm -f host1 || true

# Save and load each image, so we can use them in the inner host containers.
./build_node.sh
docker save --output calico-node.tar calico/node
if [ ! -e busybox.tar ] ; then
    docker pull busybox:latest
    docker save --output busybox.tar busybox:latest
fi
if [ ! -e nsenter.tar ] ; then
    docker pull jpetazzo/nsenter:latest
    docker save --output nsenter.tar jpetazzo/nsenter:latest
fi
if [ ! -e etcd.tar ] ; then
    docker pull quay.io/coreos/etcd:v2.0.10
    docker save --output etcd.tar quay.io/coreos/etcd:v2.0.10
fi

./create_binary.sh
docker run --privileged -v `pwd`:/code --name host1 -tid jpetazzo/dind

# Load each of the images saved above.
docker exec -t host1 bash -c \
 'while ! docker ps; do sleep 1; done && \
 docker load --input /code/calico-node.tar && \
 docker load --input /code/busybox.tar && \
 docker load --input /code/nsenter.tar && \
 docker load --input /code/etcd.tar'

# Run the FVs. Need to run from the /code directory since the tests expect
# to be run from the root of the codebase.
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/mainline.sh'
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/add_container.sh'
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/add_ip.sh'
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/arg_parsing.sh'
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/profile_commands.sh'
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/no_powerstrip.sh'
docker exec -t host1 bash -c 'cd /code && sudo ./calico_containers/tests/fv/diags.sh'

docker exec -t host1 bash -c 'docker rm -f $(docker ps -qa) ; \
                              docker rmi $(docker images -qa)' || true
docker rm -f host1 || true

echo "All tests have passed."
