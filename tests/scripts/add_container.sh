#!/bin/sh
set -e
set -x

show_commands() {
dist/calicoctl status
dist/calicoctl shownodes --detailed
dist/calicoctl ipv4 pool show
dist/calicoctl profile show --detailed
}

# Set it up
docker rm -f node etcd || true
docker run -d -p 4001:4001 --name etcd quay.io/coreos/etcd:v0.4.6
dist/calicoctl reset || true

docker run -tid --name=node busybox
dist/calicoctl node --ip=127.0.0.1
dist/calicoctl profile add TEST_GROUP

# Add endpoints
export DOCKER_HOST=localhost:2377
while ! docker ps; do
echo "Waiting for powerstrip to come up"
  sleep 1
done

dist/calicoctl container add node 192.168.1.1
dist/calicoctl profile TEST_GROUP add member node

while ! ip route |grep 192.168.1.1; do
echo "Waiting for felix to add route"
  sleep 1
done