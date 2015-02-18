#!/bin/sh
set -e
set -x

# Set it up
docker rm -f node1 node2 || true
python calicoctl.py reset
docker run -tid --name=node2 busybox
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
python calicoctl.py container add node2 192.168.1.2

python calicoctl.py group addmember TEST_GROUP node1
python calicoctl.py group addmember TEST_GROUP node2

# Check the config looks good
python calicoctl.py status
python calicoctl.py shownodes
python calicoctl.py shownodes --detailed
python calicoctl.py ipv4 pool show
python calicoctl.py group show
python calicoctl.py group show --detailed

# Check it works
while ! docker exec node1 ping 192.168.1.2 -c 1 -W 1; do
echo "Waiting for network to come up"
  sleep 1
done

docker exec node1 ping 192.168.1.1 -c 1
docker exec node1 ping 192.168.1.2 -c 1
docker exec node2 ping 192.168.1.1 -c 1
docker exec node2 ping 192.168.1.2 -c 1

# Record diags
#python calicoctl.py diags

# Tear it down
python calicoctl.py group removemember TEST_GROUP node1
python calicoctl.py group removemember TEST_GROUP node2
python calicoctl.py group remove TEST_GROUP
# BROKEN python calicoctl.py group show --detailed

python calicoctl.py container remove node1
python calicoctl.py container remove node2
python calicoctl.py shownodes --detailed

python calicoctl.py ipv4 pool del 192.168.0.0/16
# BROKEN python calicoctl.py ipv4 pool show

python calicoctl.py node stop
export DOCKER_HOST=
python calicoctl.py master stop
