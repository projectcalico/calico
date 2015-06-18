# Running calico-docker networking on a Docker Swarm.
The following instructions configure a Docker Swarm networked using Calico.  In this tutorial, we will do the following.
- Configure Docker Swarm on a VM cluster.
- Configure etcd and Calico on our cluster.
- Provision workloads on the Swarm, and check they can communicate.

## Prerequisites
To complete this demo, make sure you have the following prerequisites.
- Four servers (VMs or bare-metal) with Docker 1.4 or later installed.
  - 1 client (to control the Swarm)
  - 1 Swarm manager
  - 2 Swarm nodes

## Installing Swarm on your cluster
Our Docker Swarm will consist of 2 nodes and a Swarm master.  We will use the fourth server as the client to control our swarm.  We'll use the token-based discovery backend to configure our Swarm.

First, let us create the token which will identify our swarm.  Run the following on your client node:
```
docker pull swarm
docker run --rm swarm create
``` 

The second command will print a unique cluster ID token which we must use to configure our swarm.  We'll reference this value in the tutorial as <swarm_token>.

Now that we've got a token, we can begin to configure our Swarm.  First, let's join each of our two Swarm nodes to the cluster.  Run the following commands on each node, replacing <swarm_token> with the token from above, and <node_ip> with the IP address the master node will use to communicate with this node. 
```
docker run -d swarm join --addr=<node_ip>:2377 token://<swarm_token>
```

Let's now configure the Swarm manager on the master node.  To do this, run the following:
```
docker run -d -p <swarm_port>:2375 swarm manage token://<swarm_token>
```

Note that <swarm_port> in the above command can be any unused TCP port on the manager server.  This is the port the client will use to communicate with the Swarm manager daemon.

At this point, the Swarm agents are running on our cluster.  However, the cluster won't be complete until Calico is installed and running on the Swarm nodes.

## Installing etcd
Calico requires etcd, so let's install it on our cluster.  For this example, we'll only configure a single node etcd cluster.  However, in a production environment, a minimum of a three node etcd cluster is reccomended.

Let's install etcd on our master node.  Run the following to download the etcd binaries.
```
# Download etcd for Linux 
curl -L https://github.com/coreos/etcd/releases/download/v2.0.11/etcd-v2.0.11-linux-amd64.tar.gz -o etcd-v2.0.11-linux-amd64.tar.gz
tar xzvf etcd-v2.0.11-linux-amd64.tar.gz

# Move the binaries to /usr/local/bin for easy access.
cd etcd-v2.0.11-linux-amd64
sudo cp etcd /usr/local/bin
sudo cp etcdctl /usr/local/bin
```

Now that etcd is installed, let's run our single node cluster. Replace each <master_ip> with the reachable IP address of your Swarm manager node.
```
etcd -name etcd0  -advertise-client-urls http://<master_ip>:2379,http://<master_ip>:4001  -listen-client-urls http://0.0.0.0:2379,http://0.0.0.0:4001  -initial-advertise-peer-urls http://<master_ip>:2380  -listen-peer-urls http://0.0.0.0:2380  -initial-cluster-token etcd-cluster-1  -initial-cluster etcd0=http://<master_ip>:2380 -initial-cluster-state new

```

## Installing calicoctl on each Swarm node
Now that etcd is running, we can install calico.  On each node, run these commands to set up Calico:
```
# Download calicoctl and make it executable:
wget https://github.com/Metaswitch/calico-docker/releases/download/v0.4.5/calicoctl
chmod +x ./calicoctl

# Point this node at the etcd cluster
ETCD_AUTHORITY=<master_ip>:4001

# Configure local Docker requests to be routed through Powerstrip.
export DOCKER_HOST=localhost:2377

# Start the calico node service:
sudo ./calicoctl node --ip=<node_ip>
```

## Create containers and check connectivity.
At this point, we should have a fully configured, Calico networked Swarm cluster.  However, there are no workloads
running on our cluster.  Let's create a few containers and check their connectivity.

First, create profiles using calicoctl.  These profiles will allow our containers to communicate.
```
./calicoctl profile add PROF_A_C_E
./calicoctl profile add PROF_B
./calicoctl profile add PROF_D
```

Now, lets create the containers.
```
docker run -e CALICO_IP=192.168.1.1 CALICO_PROFILE=PROF_A_C_E --name workload-A -tid busybox
docker run -e CALICO_IP=192.168.1.2 CALICO_PROFILE=PROF_B --name workload-B -tid busybox
docker run -e CALICO_IP=192.168.1.3 CALICO_PROFILE=PROF_A_C_E --name workload-C -tid busybox
docker run -e CALICO_IP=192.168.1.4 CALICO_PROFILE=PROF_D --name workload-D -tid busybox
docker run -e CALICO_IP=192.168.1.5 CALICO_PROFILE=PROF_A_C_E --name workload-E -tid busybox
```

## Next steps
TODO
