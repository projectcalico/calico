#!/bin/sh
set -e
set -x
show_commands() {
dist/calicoctl status
dist/calicoctl shownodes --detailed
dist/calicoctl ipv4 pool show
dist/calicoctl group show --detailed
}

# Set it up
docker rm -f node1 node2 etcd || true
docker run -d -p 4001:4001 --name etcd quay.io/coreos/etcd:v0.4.6
dist/calicoctl reset || true

show_commands
#docker run -tid --name=node2 busybox
dist/calicoctl master --ip=172.17.8.10
dist/calicoctl node --ip=172.17.8.10
dist/calicoctl group add TEST_GROUP

# Add endpoints
export DOCKER_HOST=localhost:2377
while ! docker ps; do
echo "Waiting for powerstrip to come up"
  sleep 1
done
docker run -e CALICO_IP=192.168.1.1 -tid --name=node1 busybox
docker run -e CALICO_IP=192.168.1.2 -tid --name=node2 busybox 
#dist/calicoctl container add node2 192.168.1.2

dist/calicoctl group addmember TEST_GROUP node1
dist/calicoctl group addmember TEST_GROUP node2

# Check the config looks good - standard set of show commands plus the non-detailed ones for
# completeness.
show_commands
dist/calicoctl shownodes
dist/calicoctl group show

# Check it works
while ! docker exec node1 ping 192.168.1.2 -c 1 -W 1; do
echo "Waiting for network to come up"
  sleep 1
done

docker exec node1 ping 192.168.1.1 -c 1
docker exec node1 ping 192.168.1.2 -c 1
docker exec node2 ping 192.168.1.1 -c 1
docker exec node2 ping 192.168.1.2 -c 1

# Record diags - works, but it's just s bit slow.
#dist/calicoctl diags

# Tear it down
dist/calicoctl group removemember TEST_GROUP node1
dist/calicoctl group removemember TEST_GROUP node2
dist/calicoctl group remove TEST_GROUP
show_commands

dist/calicoctl container remove node1
dist/calicoctl container remove node2
show_commands

dist/calicoctl ipv4 pool del 192.168.0.0/16
show_commands

dist/calicoctl node stop
export DOCKER_HOST=
dist/calicoctl master stop
show_commands
