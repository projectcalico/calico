#!/bin/sh
set -e
set -x
show_commands() {
python calicoctl.py status
python calicoctl.py shownodes --detailed
python calicoctl.py ipv4 pool show
python calicoctl.py group show --detailed
}

# Set it up
docker rm -f node1 node2 etcd || true
docker run -d -p 4001:4001 --name etcd quay.io/coreos/etcd:v0.4.6
python calicoctl.py reset || true

show_commands
#docker run -tid --name=node2 busybox
python calicoctl.py master --ip=172.17.8.10
python calicoctl.py node --ip=172.17.8.10
python calicoctl.py group add TEST_GROUP

# Add endpoints
export DOCKER_HOST=localhost:2377
while ! docker ps; do
echo "Waiting for powerstrip to come up"
  sleep 1
done
docker run -e CALICO_IP=192.168.1.1 -tid --name=node1 busybox
docker run -e CALICO_IP=192.168.1.2 -tid --name=node2 busybox 
#python calicoctl.py container add node2 192.168.1.2

python calicoctl.py group addmember TEST_GROUP node1
python calicoctl.py group addmember TEST_GROUP node2

# Check the config looks good - standard set of show commands plus the non-detailed ones for
# completeness.
show_commands
python calicoctl.py shownodes
python calicoctl.py group show

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
#python calicoctl.py diags

# Tear it down
python calicoctl.py group removemember TEST_GROUP node1
python calicoctl.py group removemember TEST_GROUP node2
python calicoctl.py group remove TEST_GROUP
show_commands

python calicoctl.py container remove node1
python calicoctl.py container remove node2
show_commands

python calicoctl.py ipv4 pool del 192.168.0.0/16
show_commands

python calicoctl.py node stop
export DOCKER_HOST=
python calicoctl.py master stop
show_commands
