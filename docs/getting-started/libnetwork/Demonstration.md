<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.11.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Calico as a libnetwork plugin.
This demonstration uses Docker's native 
[libnetwork network driver](https://github.com/docker/libnetwork), available 
from Docker 1.9 release and above.

## Environment
This demonstration makes some assumptions about the environment you have. See 
[Environment Setup](EnvironmentSetup.md) for instructions on getting an 
appropriate environment.

If you have everything set up properly you should have `calicoctl` in your 
`$PATH`, and two hosts called `calico-01` and `calico-02`.

## Starting Calico services<a id="calico-services"></a>

Once you have your cluster up and running, start calico on all the nodes

On calico-01

    sudo calicoctl node --libnetwork

On calico-02

    sudo calicoctl node --libnetwork

This will start a container on each host. Check they are running

    docker ps

You should see output like this on each node

    vagrant@calico-01:~$ docker ps
    CONTAINER ID        IMAGE                           COMMAND                  CREATED             STATUS              PORTS               NAMES
    eec9ebbfb486        calico/node-libnetwork:latest   "./start.sh"             21 seconds ago      Up 19 seconds                           calico-libnetwork
    ffe6cb403e9b        calico/node:latest              "/sbin/my_init"          21 seconds ago      Up 20 seconds                           calico-node

## Creating networked endpoints

As of Docker 1.9, the integration of Docker with libnetwork introduces a new
mechanism to provide networking for Docker containers.

The new command `docker network` can be used to create a logical network.  
A new flag is introduced to `docker run` to join a container to a particular 
network:  `--net <network>`.

So let's go ahead and create some networks and start a few containers 
on each host spread between these networks.

Create three networks.  If you are not running in cloud 
environment run the following on either host: 

    docker network create --driver=calico --subnet=192.168.0.0/24 net1
    docker network create --driver=calico --subnet=192.168.1.0/24 net2
    docker network create --driver=calico --subnet=192.168.2.0/24 net3
    
If you are running in a cloud environment (AWS, DigitalOcean, GCE), you will 
need to configure the network with `ipip` and `nat-outgoing` options.  On
either host, run:

    docker network create --driver=calico --opt nat-outgoing=true --opt ipip=true --subnet=192.168.0.0/24 net1
    docker network create --driver=calico --opt nat-outgoing=true --opt ipip=true --subnet=192.168.1.0/24 net2
    docker network create --driver=calico --opt nat-outgoing=true --opt ipip=true --subnet=192.168.2.0/24 net3

Note that we use the Calico driver `calico`.  This driver is run within 
the calico-node container.  We explicitly choose an IP Pool for each network
rather than using the default selections - this is to avoid potential conflicts
with the default NAT IP assignment used by VirtualBox.  Depending on your
specific environment, you may need to choose different IP Pool CIDRs.

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

    docker exec workload-A ping -c 4  `docker inspect --format "{{ .NetworkSettings.Networks.net2.IPAddress }}" workload-B`
    
These pings will fail.

To test connectivity between A and D which are on different hosts, it is 
necessary to run the `docker inspect` command on the host for D (calico-02) 
and then run the ping command on the host for A (calico-01).
    
On calico-02

    docker inspect --format "{{ .NetworkSettings.Networks.net3.IPAddress }}" workload-D
    
This returns the IP address of workload-D.

On calico-01

    docker exec workload-A ping -c 4 <IP address of D>

replacing the `<...>` with the appropriate IP address of D.  These pings will
fail.

To see the list of networks, use

    docker network ls

## IPv6 (Optional)

IPv6 networking is not yet supported for Calico networking with libnetwork.