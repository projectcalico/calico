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
#echo "Sleep for 5 seconds while everything comes up"
#sleep 5
#ping X Y  (many times)

# Check it looks good
#

#
#python calicoctl.py container remove

# Tear it down
#python calicoctl.py diags
#python calicoctl.py group removemember TEST_GROUP
#python calicoctl.py group remove TEST_GROUP
#python calicoctl.py container remove
#python calicoctl.py container remove
#python calicoctl.py ipv4 pool del
#python calicoctl.py node stop
#python calicoctl.py master stop
#python calicoctl.py reset
