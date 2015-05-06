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

# Run the mainline test.
run_test() {
# Expects two parameters.  The IP addresses to use for the two nodes.
cfg_ip1=$1
cfg_ip2=$2

# Set it up
docker rm -f node1 node2 etcd || true
docker run -d --net=host --name etcd quay.io/coreos/etcd:v2.0.10
dist/calicoctl reset || true

show_commands
dist/calicoctl node --ip=127.0.0.1
dist/calicoctl profile add TEST_GROUP

# Add endpoints
export DOCKER_HOST=localhost:2377
while ! docker ps; do
echo "Waiting for powerstrip to come up"
  sleep 1
done
docker run -e CALICO_IP=$cfg_ip1 -tid --name=node1 busybox
docker run -e CALICO_IP=$cfg_ip2 -tid --name=node2 busybox

# Perform a docker inspect to extract the configured IP addresses.
node1_ip="$(docker inspect node1 | grep IPAddress)"
node1_ip="${node1_ip#*: \"}"
node1_ip="${node1_ip%\"*}"
echo "Node 1 IP address is $node1_ip"

node2_ip="$(docker inspect node2 | grep IPAddress)"
node2_ip="${node2_ip#*: \"}"
node2_ip="${node2_ip%\"*}"
echo "Node 2 IP address is $node2_ip"

# Configure the nodes with the same profiles.
dist/calicoctl profile TEST_GROUP member add node1
dist/calicoctl profile TEST_GROUP member add node2

# Check the config looks good - standard set of show commands plus the
# non-detailed ones for completeness.
show_commands
dist/calicoctl shownodes
dist/calicoctl profile show

# Check it works
while ! docker exec node1 ping $node2_ip -c 1 -W 1; do
echo "Waiting for network to come up"
  sleep 1
done

docker exec node1 ping $node1_ip -c 1
docker exec node1 ping $node2_ip -c 1
docker exec node2 ping $node1_ip -c 1
docker exec node2 ping $node2_ip -c 1

# Record diags - works, but it's just s bit slow.
#dist/calicoctl diags

# Tear it down
dist/calicoctl profile remove TEST_GROUP
show_commands

dist/calicoctl container remove node1
dist/calicoctl container remove node2
show_commands

dist/calicoctl pool remove 192.168.0.0/16
show_commands

export DOCKER_HOST=
dist/calicoctl node stop
show_commands
}

# Run the test using auto assignment of IPs
run_test "auto" "auto"

# Run the test using hard coded IPV4 assignments
run_test "192.168.1.1" "192.168.1.2"

echo "Tests completed successfully"
