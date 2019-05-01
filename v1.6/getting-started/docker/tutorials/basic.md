---
title: Calico as a Docker network plugin
canonical_url: 'https://docs.projectcalico.org/v1.6/getting-started/docker/tutorials/basic'
---


This tutorial describes how to set up a Calico cluster in a Docker environment
using Docker's native networking framework (built around libnetwork) with
Calico specific network and IPAM drivers.

The libnetwork networking framework is available in Docker in release 1.9 and
above.

Using the Calico network driver, the required network setup and configuration
for networking containers using Calico is handled automatically as part of the
standard network and container lifecycle.  Provided the network is created
using the Calico driver, creating a container using that network will
automatically add the container to the Calico network, creating all necessary
Calico configuration and setting up the interface and routes in the container
accordingly.

The Calico IPAM driver may be used in addition to the the Calico network
driver.  This provides IP address management using the configured Calico IP
Pools as address pools for the container, preferentially selecting sub-blocks
of IPs for a particular host.

## 1. Environment setup

To run through the worked example in this tutorial you will to set up two hosts
with a number of installation dependencies.

Follow the instructions in one of the tutorials below to set up a virtualized
environment using Vagrant or a cloud service - be sure to follow the
appropriate instructions for _Calico as a Docker network plugin_.

- [Vagrant install with CoreOS]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/vagrant-coreos/)
- [Vagrant install with Ubuntu]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/vagrant-ubuntu)
- [Amazon Web Services (AWS)]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/aws)
- [Google Compute Engine (GCE)]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/gce)
- [DigitalOcean]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/digital-ocean)

Altenatively, you can manually configure your hosts.
- [Manual setup]({{site.baseurl}}/{{page.version}}/getting-started/docker/installation/manual)

If you have everything set up properly you should have `calicoctl` in your
`$PATH`, and two hosts called `calico-01` and `calico-02`.

## 2. Starting Calico services

Once you have your cluster up and running, start calico on all the nodes,
specifying the `--libnetwork` option to start libnetwork plugin in calico-node.

On calico-01

    sudo ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> calicoctl node --libnetwork

On calico-02

    sudo ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> calicoctl node --libnetwork

This will start a container on each host. Check they are running

    docker ps

You should see output like this on each node

    vagrant@calico-01:~$ docker ps
    CONTAINER ID        IMAGE                COMMAND             CREATED             STATUS              PORTS               NAMES
    408bd2b9ba53        calico/node:v0.23.1   "start_runit"       About an hour ago   Up About an hour                        calico-node

## 3. Create the networks

This worked example creates three Docker networks, where containers on a
particular network are isolated from containers in the other networks.

### 3.1 Select the IPAM driver

Before we create the networks, we need to select which IP address management
(IPAM) driver we will use.  There are two options, where we suggest using the
Calico IPAM driver where possible.

#### The Calico IPAM driver

The Calico IPAM driver provides address assignment that is geared towards
a Calico deployment where scaling is important, and port-mapping for the
containers is not required.

The Calico IPAM driver assigns addresses with host aggregation - this is a more
efficient approach for Calico requiring fewer programmed routes.  IPv6
addresses are supported, although with the current Docker API, it is not
possible to have an IPv6-only network, and (unlike the IPv4 behavior) it is
necessary to specify a subnet from which to assign addresses.

When running in a cloud environment we need to also set `ipip` and
`nat-outgoing` options. If using the Calico IPAM driver `calico`, the
`ipip` and `nat-outgoing` options are configured on the Calico IP Pool.

#### The default IPAM driver.

When a network uses the Docker default IPAM driver, a new container on the
network is allocated an IP address from the network's CIDR. The Calico plugin
assigns this IP address to the Calico interface on the container. In addition to
this, the container connects to the host's Docker gateway bridge over a separate
interface on the container. All non-network traffic (i.e. destinations outside
the CIDR) is routed via the Docker gateway bridge and may not be subjected to the
Calico policy.

Since the container is connected to the Docker gateway bridge, it can utilize
Docker's port mapping feature.  However, it is important to note that using
Docker's port-mapping feature is not secured by Calico policy since the packets
are routed via the Docker bridge, rather than through the Calico interfaces.
(For more information on port-forwarding with Calico, check out the [Expose
Ports to Internet guide]({{site.baseurl}}/{{page.version}}/usage/external-connectivity).)

When running in a cloud environment we need to also set `ipip` and
`nat-outgoing` options. If using the default IPAM driver, `ipip` and
`nat-outgoing` are specified as options on the `network create`.

### 3.2 Create the network

So, with the IPAM driver selected, we can start creating some networks.

We specify the Calico networking driver (`calico`) when creating the network,
and optionally specify the Calico IPAM driver (`calico`) if you chose to use
Calico IPAM.

For this worked example, we explicitly choose a CIDR for each network
rather than using default selections - this is to avoid potential conflicts
with the default NAT IP assignment used by VirtualBox.  Depending on your
specific environment, you may need to choose different CIDRs.

So, once you have decided which type of network to create, following the
appropriate instructions for one of *a)*, *b)*, *c)* or *d)*.

For AWS, omit the `--ipip` or `--opt ipip=true` in the below, and `Change Source/Dest. Check` on your instances with
the following EC2 CLI command or by right clicking the instance in the EC2
console, and selecting it from the Networking submenu.

    aws ec2 modify-instance-attribute --instance-id <instance_id> --source-dest-check "{\"Value\": false}"

#### a) Networking using Calico IPAM in a non-cloud environment

For Calico IPAM in a non-cloud environment, you need to first create a Calico
IP Pool with no additional options.  Here we create a pool with CIDR
192.168.0.0/16.

    calicoctl pool add 192.168.0.0/16

To create the networks, run:

    docker network create --driver calico --ipam-driver calico net1
    docker network create --driver calico --ipam-driver calico net2
    docker network create --driver calico --ipam-driver calico net3

#### b) Networking using Calico IPAM in a cloud environment

For Calico IPAM in a cloud environment that doesn't enable direct container to
container communication (DigitalOcean, GCE), you need to first create a Calico
IP Pool using the `calicoctl pool add` command specifying the `ipip` and
`nat-outgoing` options.  Here we create a pool with CIDR 192.168.0.0/16.

    calicoctl pool add 192.168.0.0/16 --ipip --nat-outgoing

To create the networks, run:

    docker network create --driver calico --ipam-driver calico net1
    docker network create --driver calico --ipam-driver calico net2
    docker network create --driver calico --ipam-driver calico net3

#### c) Networking using default IPAM in a non-cloud environment

For default IPAM in a non-cloud environment, run:

    docker network create --driver calico --subnet=192.168.0.0/24 net1
    docker network create --driver calico --subnet=192.168.1.0/24 net2
    docker network create --driver calico --subnet=192.168.2.0/24 net3

#### d) Networking using default IPAM in a cloud environment

For default IPAM in a cloud environment (AWS, DigitalOcean, GCE), run:

    docker network create --driver calico --opt nat-outgoing=true --opt ipip=true --subnet=192.168.0.0/24 net1
    docker network create --driver calico --opt nat-outgoing=true --opt ipip=true --subnet=192.168.1.0/24 net2
    docker network create --driver calico --opt nat-outgoing=true --opt ipip=true --subnet=192.168.2.0/24 net3


## 4. Create the workloads in the networks

With the networks created, let's start some containers on each host spread
between these networks.

On calico-01

    docker run --net net1 --name workload-A -tid busybox
    docker run --net net2 --name workload-B -tid busybox
    docker run --net net1 --name workload-C -tid busybox

On calico-02

    docker run --net net3 --name workload-D -tid busybox
    docker run --net net1 --name workload-E -tid busybox

By default, networks are configured so that their members can communicate with
one another, but workloads in other networks cannot reach them.  A, C and E are
all in the same network so should be able to ping each other.  B and D are in
their own networks so shouldn't be able to ping anyone else.

## 5. Validation

On calico-01 check that A can ping C and E.  We can ping workloads within a
containers networks by name.

    docker exec workload-A ping -c 4 workload-C.net1
    docker exec workload-A ping -c 4 workload-E.net1

Also check that A cannot ping B or D.  This is slightly trickier because the
hostnames for different networks will not be added to the host configuration of
the container - so we need to determine the IP addresses assigned to containers
B and D.

Since A and B are on the same host, we can run a single command that inspects
the IP address and issues the ping.  On calico-01

    docker exec workload-A ping -c 4  `docker inspect --format "{% raw %}{{ .NetworkSettings.Networks.net2.IPAddress }}{% endraw %}" workload-B`

These pings will fail.

To test connectivity between A and D which are on different hosts, it is
necessary to run the `docker inspect` command on the host for D (calico-02)
and then run the ping command on the host for A (calico-01).

On calico-02

    docker inspect --format "{% raw %}{{ .NetworkSettings.Networks.net3.IPAddress }}{% endraw %}" workload-D

This returns the IP address of workload-D.

On calico-01

    docker exec workload-A ping -c 4 <IP address of D>

replacing the `<...>` with the appropriate IP address of D.  These pings will
fail.

To see the list of networks, use

    docker network ls

## Assign Static IP when Starting a Container

With the release of Docker 1.10, support has been added to allow users to
configure a specific IP address when creating a container.  In order to use
this feature, Docker requires that you specify the `--subnet` parameter when running
`docker network create`.  This parameter can be used in any of the four **"Create the
network"** sets above.

If you are using the Calico IPAM driver, the `--subnet` value must be the same
CIDR as an existing Calico IP pool.  So if you create a Calico IP pool for
`192.168.1.0/24`, you can use `--subnet=192.168.1.0/24` as a valid subnet.

For example, the following commands:
 - create a Calico IP pool
 - create a Docker network using the IP pool
 - create a container using a specific IP address from the pool

```
calicoctl pool add 192.168.1.0/24
docker network create --driver calico --ipam-driver calico --subnet=192.168.1.0/24 my_net
docker run --net my_net --name my_workload --ip 192.168.1.100 -tid busybox
```

## IPv6 (Optional)

IPv6 networking is also supported.  If you are using IPv6 address spaces as
well, start your Calico node passing in both the IPv4 and IPv6 addresses of
the host.

For example:

    calicoctl node --ip=172.17.8.101 --ip6=fd80:24e2:f998:72d7::1 --libnetwork

See the [IPv6 tutorial]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/ipv6) for a worked example.


## Advanced network policy

If you are using both the Calico network driver and the Calico IPAM driver
it is possible to apply advanced policy to the network.

For more details, read
[Accessing Calico policy with Calico as a network plugin]({{site.baseurl}}/{{page.version}}/getting-started/docker/tutorials/advanced-policy).

## Make a container reachable from the Host-Interface (Internet)
If you're interested in using port-forwarding, we have a working example on how
to [expose a container port to the internet]({{site.baseurl}}/{{page.version}}/usage/external-connectivity)
when using Calico.
