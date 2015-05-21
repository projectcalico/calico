#!/bin/sh
set -e
set -x

CALICO="dist/calicoctl"
#CALICO="python calicoctl.py"

# Set it up
docker rm -f node1 node2 etcd || true
docker run -d --net=host --name etcd quay.io/coreos/etcd:v2.0.10
$CALICO reset || true

$CALICO node --ip=172.17.8.10
$CALICO profile add TEST_GROUP

# Add endpoints
export DOCKER_HOST=localhost:2377
while ! docker ps; do
echo "Waiting for powerstrip to come up"
  sleep 1
done

docker run -e CALICO_IP=192.168.1.1 -tid --name=node1 busybox
docker run -tid --name=node2 busybox
$CALICO container add node2 192.168.1.2 --interface=hello

$CALICO profile TEST_GROUP member add node1
$CALICO profile TEST_GROUP member add node2

# Check it works
while ! docker exec node1 ping 192.168.1.2 -c 1 -W 1; do
echo "Waiting for network to come up"
  sleep 1
done

# Add two more addresses to node1 and one more to node2
$CALICO container node1 ip add 192.168.2.1
$CALICO container node1 ip add 192.168.3.1

$CALICO container node2 ip add 192.168.2.2 --interface=hello

docker exec node1 ping 192.168.2.2 -c 1
docker exec node2 ping 192.168.1.1 -c 1
docker exec node2 ping 192.168.2.1 -c 1
docker exec node2 ping 192.168.3.1 -c 1
$CALICO shownodes --detailed

# Now stop and restart node 1 and node 2.
sudo docker -H=localhost:2377 stop node1
sudo docker -H=localhost:2377 stop node2
sudo docker -H=localhost:2377 start node1
sudo docker -H=localhost:2377 start node2

# Wait for the network to come up.
while ! docker exec node1 ping 192.168.1.2 -c 1 -W 1; do
echo "Waiting for network to come up"
  sleep 1
done

# Test pings between the IPs.
docker exec node1 ping 192.168.1.2 -c 1
docker exec node1 ping 192.168.2.2 -c 1
docker exec node2 ping 192.168.1.1 -c 1
docker exec node2 ping 192.168.2.1 -c 1
docker exec node2 ping 192.168.3.1 -c 1
$CALICO shownodes --detailed

# Now remove and check pings to the removed addresses no longer work.
$CALICO container node1 ip remove 192.168.2.1
$CALICO container node2 ip remove 192.168.2.2 --interface=hello
docker exec node1 ping 192.168.1.2 -c 1
docker exec node2 ping 192.168.1.1 -c 1
(! docker exec node1 ping 192.168.2.2 -c 1 -W 1)
(! docker exec node2 ping 192.168.2.1 -c 1 -W 1)
docker exec node2 ping 192.168.3.1 -c 1
$CALICO shownodes --detailed

# Check that we can't remove addresses twice
(! $CALICO container node1 ip remove 192.168.2.1)

echo "Tests completed successfully"