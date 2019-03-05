---
Title: Runing Calico on a Docker Swarm
---

The following tutorial provides instructions for configuring a Docker Swarm
cluster that is networked using Calico as a Docker network plugin. In this
tutorial, we will do the following:

* Configure etcd and Calico on a cluster.
* Configure Docker Swarm on our VM cluster.

## 1. Prerequisites

This tutorial assumes that your client and each node in your cluster
have `calicoctl`, etcd, and Docker 1.9 or greater installed in your `$PATH`.
See our [Prerequisite tutorial]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/manual)
for instructions on getting this properly set up.

To make things simpler, let's store some commonly used values as environment
variables on each **Swarm node**. We will use these variables throughout the
tutorial.

    $ export MANAGER_IP=<Manager's IP Address>
    $ export NODE_IP=<This Node's IP Address>

## 2. Configure etcd

Calico requires etcd, so let's run it on our cluster. We need to start etcd
with the IP address of the manager server, so ensure that you have set the
`MANAGER_IP` environment, as seen above.

    $ etcd -advertise-client-urls http://$MANAGER_IP:2379 \
    -listen-client-urls http://0.0.0.0:2379  &

For this example, we'll only configure a single node etcd cluster on our master
node. However, in a production environment, a minimum size of three nodes is
recommended and can run anywhere that is accessible to the cluster.

## 3. Configure Calico

Now that etcd is running, we can run Calico.

Now, start the Calico node service on each node in the cluster.

    $ sudo ETCD_AUTHORITY=$MANAGER_IP:2379 calicoctl node --libnetwork --ip=$NODE_IP

## 4. Configure Swarm Cluster

Now that Calico networking is configured on our cluster, let's join our nodes
into a Docker Swarm cluster.

We'll use the token based discovery backend, so let's first create the token
which will identify our swarm. To do this, run the following on our client.
Note that docker commands may need to be run with root privileges depending on
your docker installation.

    $ docker run --rm swarm create

This command will print a unique cluster ID token which we must use to
configure our Swarm. We'll reference this value in the tutorial as
`<swarm_token>`. Your token should look something like this:

    d435dc104abdd89af24ae2392c7338ce

## 5. Configure Swarm Nodes

Before we configure our Swarm, we will need to start the Docker daemon and
point the cluster-store to our running instance of etcd.

    $ sudo docker daemon -H tcp://0.0.0.0:2375 -H unix:///var/run/docker.sock --cluster-store=etcd://$MANAGER_IP:2379 &

Now that we've got a token and a properly running daemon, we can begin to
configure our Swarm. First, let's join each of our Swarm nodes to the cluster.

Run the following commands on each node, replacing `<swarm_token>` with your
given token.

    $ docker run -d swarm join --addr=$NODE_IP:2375 token://<swarm_token>

## 6. Configure Swarm Manager

Let's now configure the Swarm manager. Note that `<swarm_port>` in the
following command can be any unused TCP port on the manager server. This is
the port the client will use to communicate with the Swarm manager daemon.

    $ docker run -d -p <swarm_port>:2375 swarm manage token://<swarm_token>

## 7. Testing Docker Swarm

At this point we should have a fully configured Calico networked Swarm cluster.
However, there are no workloads running on our cluster. Let's create a few
containers and check their connectivity. We can run the following commands on
the client against the Swarm Manager using the -H flag.

First, set the SWARM_PORT environment variable on the client to the value
chosen when configuring the Swarm manager.

    $ export SWARM_PORT=<swarm_port>

Then, we will configure three networks using the Calico network and Calico
IPAM drivers. Note that we need to first create a pool of allowable IP
addresses for the containers. Here we create a pool with CIDR 192.168.0.0/16.

    $ calicoctl pool add 192.168.0.0/16

To create the networks, run:

    $ docker -H $MANAGER_IP:$SWARM_PORT network create --driver=calico --ipam-driver calico net1
    $ docker -H $MANAGER_IP:$SWARM_PORT network create --driver=calico --ipam-driver calico net2
    $ docker -H $MANAGER_IP:$SWARM_PORT network create --driver=calico --ipam-driver calico net3

Now, let's create some containers on our cluster. Run the following commands on
your client.

    $ docker -H $MANAGER_IP:$SWARM_PORT run --net net1 --name workload-A -tid busybox
    $ docker -H $MANAGER_IP:$SWARM_PORT run --net net2 --name workload-B -tid busybox
    $ docker -H $MANAGER_IP:$SWARM_PORT run --net net1 --name workload-C -tid busybox
    $ docker -H $MANAGER_IP:$SWARM_PORT run --net net3 --name workload-D -tid busybox
    $ docker -H $MANAGER_IP:$SWARM_PORT run --net net1 --name workload-E -tid busybox

We can run `ps` against the Swarm manager to check that the containers have
been created.

    $ docker -H $MANAGER_IP:$SWARM_PORT ps

You should see an output which look similar to this. Notice that the containers
have been distributed across our two Swarm nodes.

```
CONTAINER ID        IMAGE                COMMAND             CREATED             STATUS              PORTS         NAMES
11a76a439cfa        busybox              "/bin/sh"           42 minutes ago      Up 42 minutes                     swarm-node2/workload-E
9196feb986ef        busybox              "/bin/sh"           43 minutes ago      Up 42 minutes                     swarm-node1/workload-D
6971bed91ea7        busybox              "/bin/sh"           43 minutes ago      Up 43 minutes                     swarm-node2/workload-C
4ad182b5cfbd        busybox              "/bin/sh"           43 minutes ago      Up 43 minutes                     swarm-node1/workload-B
58736abaf698        busybox              "/bin/sh"           44 minutes ago      Up 44 minutes                     swarm-node2/workload-A
9c22e2e3b393        calico/node:v0.4.9   "/sbin/my_init"     56 minutes ago      Up 55 minutes                     swarm-node1/calico-node
3dff7c3d76c6        calico/node:v0.4.9   "/sbin/my_init"     About an hour ago   Up 59 minutes                     swarm-node2/calico-node
```

By default, networks are configured so that their members can communicate with
one another, but workloads in other networks cannot reach them. A, C and E are
all in the same network so should be able to ping each other. B and D are in
their own networks so shouldn't be able to ping anyone else.

Verify this by pinging workloads C and E from workload A.

    $ docker -H $MANAGER_IP:$SWARM_PORT exec workload-A ping -c 4 workload-C
    $ docker -H $MANAGER_IP:$SWARM_PORT exec workload-A ping -c 4 workload-E

Also check that A cannot ping B or D. This is slightly trickier because the
hostnames for different networks will not be added to the host configuration of
the container - so we need to determine the IP addresses assigned to containers
B and D.

To find the IP address of workload B, we can run the `docker inspect` command.
Then, use the returned IP address to test connectivity between workloads A and
B. These pings should fail.

    $ export WORKLOADB_IP=`docker -H $MANAGER_IP:$SWARM_PORT inspect --format "{% raw %}{{ .NetworkSettings.Networks.net2.IPAddress }}{% endraw %}" workload-B`
    $ docker -H $MANAGER_IP:$SWARM_PORT exec workload-A ping -c 4 $WORKLOADB_IP
