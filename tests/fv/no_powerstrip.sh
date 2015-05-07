#!/bin/sh
set -e
set -x

# Execute show commands
show_commands() {
dist/calicoctl status
dist/calicoctl shownodes --detailed
dist/calicoctl pool show
dist/calicoctl profile show --detailed
}

# Set it up
docker rm -f node1 node2 etcd || true
docker run -d --net=host --name etcd quay.io/coreos/etcd:v2.0.10
dist/calicoctl reset || true

show_commands
dist/calicoctl node --ip=127.0.0.1
dist/calicoctl profile add TEST_GROUP

# Remove the environment variable such that docker run does not utilize
# powerstrip.
export DOCKER_HOST=
docker run -e CALICO_IP=192.168.1.1 -tid --name=node1 busybox
docker run -e CALICO_IP=192.168.1.2 -tid --name=node2 busybox

# Attempt to configure the nodes with the same profiles.  This will fail
# since we didn't use powerstrip to create the nodes.
(! dist/calicoctl profile TEST_GROUP member add node1)
(! dist/calicoctl profile TEST_GROUP member add node2)

# Add the nodes to Calico networking.
dist/calicoctl container add node1 192.168.1.1
dist/calicoctl container add node2 192.168.1.2

# Now add the profiles.
dist/calicoctl profile TEST_GROUP member add node1
dist/calicoctl profile TEST_GROUP member add node2

# Inspect the nodes (ensure this works without powerstrip)
docker inspect node1
docker inspect node2

# Check the config looks good - standard set of show commands plus the
# non-detailed ones for completeness.
show_commands
dist/calicoctl shownodes
dist/calicoctl profile show

# Check it works
while ! docker exec node1 ping 192.168.1.2 -c 1 -W 1; do
echo "Waiting for network to come up"
  sleep 1
done

docker exec node1 ping 192.168.1.1 -c 1
docker exec node1 ping 192.168.1.2 -c 1
docker exec node2 ping 192.168.1.1 -c 1
docker exec node2 ping 192.168.1.2 -c 1

# Tear it down
dist/calicoctl profile remove TEST_GROUP
show_commands

dist/calicoctl container remove node1
dist/calicoctl container remove node2
show_commands

dist/calicoctl pool remove 192.168.0.0/16
show_commands

dist/calicoctl node stop
show_commands

echo "Tests completed successfully"
