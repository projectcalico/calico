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

### Create the networks

So let's go ahead and create some networks and start a few containers 
on each host spread between these networks.

> Exactly how we create these networks depends on whether we are using the
> built-in libnetwork IPAM driver or the Calico IPAM driver.  For more details
> on this, see the documentation for [`calicoctl node`](../../calicoctl/node.md)
>
> Furthermore, when running in a cloud environment we need to also set
> `ipip` and `nat-outgoing` options.

In each case we use the Calico driver `calico` for networking.  This driver is
run as part of the calico-node in a calico/node-libnetwork container.  For the 
demonstration, we explicitly choose an IP Pool for each network rather than 
using the default selections - this is to avoid potential conflicts with the 
default NAT IP assignment used by VirtualBox.  Depending on your specific 
environment, you may need to choose different IP Pool CIDRs.

When the default IPAM driver is used, the pool CIDR and `ipip` and 
`nat-outgoing` configuration are specified as options on the `network create`.

When the Calico IPAM driver `calico` is used, it is necessary to create the 
Calico IP Pool in advance with the appropriate configuration for `ipip` and 
`nat-outgoing`.  The Calico IPAM driver runs alongside the Calico network
driver within the calico/node-libnetwork container.


#### Networking using default IPAM in a non-cloud environment

For default IPAM in a non-cloud environment, run: 

    docker network create --driver=calico --subnet=192.168.0.0/24 net1
    docker network create --driver=calico --subnet=192.168.1.0/24 net2
    docker network create --driver=calico --subnet=192.168.2.0/24 net3
    
#### Networking using default IPAM in a cloud environment

For default IPAM in a cloud environment (AWS, DigitalOcean, GCE), run:

    docker network create --driver=calico --opt nat-outgoing=true --opt ipip=true --subnet=192.168.0.0/24 net1
    docker network create --driver=calico --opt nat-outgoing=true --opt ipip=true --subnet=192.168.1.0/24 net2
    docker network create --driver=calico --opt nat-outgoing=true --opt ipip=true --subnet=192.168.2.0/24 net3

#### Networking using Calico IPAM in a non-cloud environment

For Calico IPAM in a non-cloud environment, you need to first create a Calico
IP Pool with no additional options.  Here we create a pool with CIDR
192.168.0.0/16.

    calicoctl pool add 192.168.0.0/16
    
To create the networks, run:

    docker network create --driver=calico --ipam-driver calico net1
    docker network create --driver=calico --ipam-driver calico net2
    docker network create --driver=calico --ipam-driver calico net3
    
#### Networking using Calico IPAM in a cloud environment

For Calico IPAM in a cloud environment (AWS, DigitalOcean, GCE), you need to 
first create a Calico IP Pool using the `calicoctl pool add` command specifying
the `ipip` and `nat-outgoing` options.  Here we create a pool with CIDR
192.168.0.0/16.

    calicoctl pool add 192.168.0.0/16 --ipip --nat-outgoing

To create the networks, run:

    docker network create --driver=calico --ipam-driver calico net1
    docker network create --driver=calico --ipam-driver calico net2
    docker network create --driver=calico --ipam-driver calico net3


### Create the workloads in the networks

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

### Validation
    
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
        
## Accessing Calico policy with libnetwork

Calico networking provides feature-rich policy for controlling access to and
from an endpoint.  However, Calico with libnetwork has some limitations when 
using the standard Docker commands for managing networks and containers.

The notable limitations are:
-  When using the Calico IPAM driver, it is not possible to join a container
   to more than one network
-  There is no built-in mechanism to create a network with complex policy 
   (currently the default policy is to allow full access between all endpoints
   connected to that network).

Despite these limitations, it is still possible to use the full Calico policy 
by accessing the Calico data directly.  Note that you must use both the Calico
Network _and_ Calico IPAM drivers together.  Using the Calico IPAM driver 
ensures _all_ traffic from the container is routed via the host vRouter and is
subject to Calico policy.  Using the default IPAM driver routes non-network
traffic (i.e. destinations outside the network CIDR) via the Docker gateway
bridge, and in this case may not be subjected to the host vRouter.

Calico policy configuration is wrapped up in a "profile" object which is
assigned to an endpoint (where we usually have a single endpoint per
container).  In Calico, a single endpoint may be configured with a list of
profiles whose policy is applied in the list order (this can be considered as
the equivalent of having a container in multiple networks).

When using [Calico with Docker default networking](../default-networking/Demonstration.md),
the use of profiles is transparent (it's necessary to explicitly create a profile
and assign them to a container).  The [`calicoctl profile`](../../calicoctl/profile.md)
commands can be used to configure a variety of rules on the profile to provide
[advanced network policy](../../AdvancedNetworkPolicy.md).

When using Calico with libnetwork, the creation of profiles and endpoints is 
handled under-the-covers.  Nonetheless, it is still possible to access the 
profile to edit the rules, or to access the endpoint configuration
to assign additional profiles.  The Calico libnetwork driver directly maps the
libnetwork Network "Id" to the Profile name, and the libnetwork "EndpointID" to
the Calico Endpoint ID.  You can use `docker network inspect` on a particular
host to obtain the network ID and the list of containers on that host that are
attached to that network.

For example, with a Docker network called "testnet1", running `docker network inspect testnet1`
returns a JSON blob that contains the network ID and the Endpoint IDs:

    host1:~$ docker network inspect testnet1
    [
        {
            "Name": "testnet1",
            "Id": "46007b33d4dd56b13ede0f10bb427ba4481e3c0efe64960b0567dd53a80d3420",
            "Scope": "global",
            "Driver": "calico",
            "IPAM": {
                "Driver": "calico",
                "Config": [
                    {}
                ]
            },
            "Containers": {
                "6a853ddc289c4754684a93115c43aa73e3d7a4dd565e272cdc3f18ee3c09ba78": {
                    "EndpointID": "5a21f63bc17feb6b9c879bbbc271594dfa1483ddf9af5171efca7a2d509908e5",
                    "MacAddress": "ee:ee:ee:ee:ee:ee",
                    "IPv4Address": "10.0.0.2/24",
                    "IPv6Address": ""
                }
            },
            "Options": {}
        }
    ]

This output shows a single container attached to that network.  The EndpointID
returned by Docker is identical to the Endpoint ID used by Calico and therefore
can be manipulated using calicoctl.  For example, you can use calicoctl to 
display the list of profiles assigned to this endpoint:

    host1:~$ calicoctl endpoint 5a21f63bc17feb6b9c879bbbc271594dfa1483ddf9af5171efca7a2d509908e5 profile show
    +------------------------------------------------------------------+
    |                               Name                               |
    +------------------------------------------------------------------+
    | 46007b33d4dd56b13ede0f10bb427ba4481e3c0efe64960b0567dd53a80d3420 |
    +------------------------------------------------------------------+

You can see that the profile name matches the Network ID returned by the
`network inspect` command above.  You can then use the profile name to manipulate
the Calico profile.  For example, here we can display the rules that are
contained in this profile:

    host1:~$ calicoctl profile 46007b33d4dd56b13ede0f10bb427ba4481e3c0efe64960b0567dd53a80d3420 rule show
    Inbound rules:
       1 allow from tag 46007b33d4dd56b13ede0f10bb427ba4481e3c0efe64960b0567dd53a80d3420
    Outbound rules:
       1 allow


## IPv6 (Optional)

IPv6 networking is supported for libnetwork when using both the Calico network
and IPAM drivers together.