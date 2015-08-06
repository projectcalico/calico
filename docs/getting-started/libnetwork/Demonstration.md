# Calico as a libnetwork plugin.
This demonstration uses Docker's native [libnetwork network driver](https://github.com/docker/libnetwork), available in the Docker (experimental channel)[https://github.com/docker/docker/tree/master/experimental] alongside the Docker 1.7 release. Docker's experimental channel is still moving fast and some of its features are not yet fully stable.

## Environment
This demonstration makes some assumptions about the environment you have. See 
[Environment Setup](EnvironmentSetup.md) for instructions on getting an 
appropriate environment.

If you have everything set up properly you should have `calicoctl` in your 
`$PATH`, and two hosts called `calico-01` and `calico-02`.

## Starting Calico services<a id="calico-services"></a>

Once you have your cluster up and running, start calico on all the nodes

On calico-01

    sudo calicoctl node

On calico-02

    sudo calicoctl node

This will start a container on each host. Check they are running

    docker ps

You should see output like this on each node

    vagrant@calico-01:~$ docker ps -a
    CONTAINER ID        IMAGE                    COMMAND                CREATED             STATUS              PORTS                                            NAMES
    39de206f7499        calico/node:v0.5.4   "/sbin/my_init"        2 minutes ago       Up 2 minutes                                                         calico-node


## Creating networked endpoints

The experimental channel version of Docker introduces a new flag to 
`docker run` to network containers:  `--publish-service <service>.<network>.<driver>`.

 * `<service>` is the name by which you want the container to be known on the network.
 * `<network>` is the name of the network to join.  Containers on different networks cannot communicate with each other.
 * `<driver>` is the name of the network driver to use.  Calico's driver is called `calico`.

So let's go ahead and start a few of containers on each host.

On calico-01

    docker run --publish-service srvA.net1.calico --name workload-A -tid busybox
    docker run --publish-service srvB.net2.calico --name workload-B -tid busybox
    docker run --publish-service srvC.net1.calico --name workload-C -tid busybox

On calico-02

    docker run --publish-service srvD.net3.calico --name workload-D -tid busybox
    docker run --publish-service srvE.net1.calico --name workload-E -tid busybox

By default, networks are configured so that their members can communicate with 
one another, but workloads in other networks cannot reach them.  A, C and E are
 all in the same network so should be able to ping each other.  B and D are in 
 their own networks so shouldn't be able to ping anyone else.
    
On calico-01 check that A can ping C and E.

    docker exec workload-A ping -c 4 srvC
    docker exec workload-A ping -c 4 srvE

Also check that A cannot ping B or D

    docker exec workload-A ping -c 4 srvB
    docker exec workload-A ping -c 4 srvD

To see the list of networks, use

    docker network ls

## IPv6 (Optional)

IPv6 networking is also supported.  If you are using IPv6 address spaces as
well, start your Calico node passing in both the IPv4 and IPv6 addresses of
the host.

For example:

    calicoctl node --ip=172.17.8.101 --ip6=fd80:24e2:f998:72d7::1
    
See the [IPv6 demonstration](DemonstrationIPv6.md) for a worked example.
