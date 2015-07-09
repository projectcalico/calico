# Getting started with Calico on Docker

>*Note that Calico uses Docker's [libnetwork network driver](https://github.com/docker/libnetwork), available in the Docker [experimental channel](https://github.com/docker/docker/tree/master/experimental) alongside the Docker 1.7 release.  This replaces Calico's use of powerstrip as a network plugin.   However, Docker's experimental channel is still moving fast and some of its features are not yet fully stable, so the stable powerstrip cluster configuration with CoreOS is still available [here](https://github.com/Metaswitch/calico-docker/blob/powerstrip-archive/docs/GettingStarted.md).*

*In order to run this example you will need a 2-node Linux cluster with Docker and etcd installed and running.*  You can do one of the following.
* Use Vagrant to set up a virtual cluster on your laptop or workstation, following these instructions: [Calico Ubuntu Vagrant][calico-ubuntu-vagrant].
* Set up a cluster manually yourself, following these instructions: [Manual Cluster Setup](./ManualClusterSetup.md).

If you want to get started quickly and easily then we recommend just using Vagrant.

If you have difficulty, try the [Troubleshooting Guide](./Troubleshooting.md).

### A note about names & addresses
In this example, we will use the server names and IP addresses from the [Calico Ubuntu Vagrant][calico-ubuntu-vagrant] example.

| hostname | IP address   |
|----------|--------------|
| ubuntu-1 | 172.17.8.101 |
| ubuntu-2 | 172.17.8.102 |

If you set up your own cluster, substitute the hostnames and IP addresses assigned to your servers.

## Starting Calico services<a id="calico-services"></a>

Once you have your cluster up and running, start calico on all the nodes

On ubuntu-1

    sudo ./calicoctl node --ip=172.17.8.101

On ubuntu-2

    sudo ./calicoctl node --ip=172.17.8.102

This will start a container. Check they are running

    sudo docker ps

You should see output like this on each node

    vagrant@ubuntu-1:~$ docker ps -a
    CONTAINER ID        IMAGE                    COMMAND                CREATED             STATUS              PORTS                                            NAMES
    39de206f7499        calico/node:v0.5.0   "/sbin/my_init"        2 minutes ago       Up 2 minutes                                                         calico-node
    5e36a7c6b7f0        quay.io/coreos/etcd  "/etcd --name calico   30 minutes ago      Up 30 minutes       0.0.0.0:4001->4001/tcp, 0.0.0.0:7001->7001/tcp   quay.io-coreos-etcd



## Creating networked endpoints

The experimental channel version of Docker introduces a new flag to `docker run` to network containers:  `--publish-service <service>.<network>.<driver>`.

 * `<service>` is the name by which you want the container to be known on the network.
 * `<network>` is the name of the network to join.  Containers on different networks cannot communicate with each other.
 * `<driver>` is the name of the network driver to use.  Calico's driver is called `calico`.

So let's go ahead and start a few of containers on each host.

On ubuntu-1

    docker run --publish-service srvA.net1.calico --name workload-A -tid busybox
    docker run --publish-service srvB.net2.calico --name workload-B -tid busybox
    docker run --publish-service srvC.net1.calico --name workload-C -tid busybox

On ubuntu-2

    docker run --publish-service srvD.net3.calico --name workload-D -tid busybox
    docker run --publish-service srvE.net1.calico --name workload-E -tid busybox

By default, networks are configured so that their members can communicate with one another, but workloads in other networks cannot reach them.  A, C and E are all in the same network so should be able to ping each other.  B and D are in their own networks so shouldn't be able to ping anyone else.

You can find out a container's IP by running

    docker inspect --format "{{ .NetworkSettings.IPAddress }}" <container name>

On ubuntu-1, find out the IP addresses of A, B and C.

    docker inspect --format "{{ .NetworkSettings.IPAddress }}" workload-A
    docker inspect --format "{{ .NetworkSettings.IPAddress }}" workload-B
    docker inspect --format "{{ .NetworkSettings.IPAddress }}" workload-C
    
On ubuntu-2, find out the IP addresses of D and E.

    docker inspect --format "{{ .NetworkSettings.IPAddress }}" workload-D
    docker inspect --format "{{ .NetworkSettings.IPAddress }}" workload-E
    
Now we know all the IP addresses, on ubuntu-1 check that A can ping C and E (substitute the IP addresses as required).

    docker exec workload-A ping -c 4 192.168.0.3
    docker exec workload-A ping -c 4 192.168.0.5

Also check that A cannot ping B or D (substitute the IP addresses as required).

    docker exec workload-A ping -c 4 192.168.0.2
    docker exec workload-A ping -c 4 192.168.0.4

Libnetwork also supports using published service names.  However, note that in the current build of libnetwork these are not yet reliable in multi-host deployments.  On ubuntu-1 try

    docker exec workload-A ping -c 4 srvC

To see the list of networks, use

    docker network ls

## IPv6 (Optional)
To connect your containers with IPv6, first make sure your Docker hosts each have an IPv6 address assigned.

On ubuntu-1

    sudo ip addr add fd80:24e2:f998:72d7::1/112 dev eth1

On ubuntu-2

    sudo ip addr add fd80:24e2:f998:72d7::2/112 dev eth1

Verify connectivity by pinging.

On ubuntu-1

    ping6 -c 4 fd80:24e2:f998:72d7::2

Then restart your calico-node processes with the `--ip6` parameter to enable v6 routing.

On ubuntu-1

    sudo ./calicoctl node --ip=172.17.8.101 --ip6=fd80:24e2:f998:72d7::1

On ubuntu-2

    sudo ./calicoctl node --ip=172.17.8.102 --ip6=fd80:24e2:f998:72d7::2

Then, you can start containers with IPv6 connectivity. By default, Calico is configured to use IPv6 addresses in the pool fd80:24e2:f998:72d6/64 (`calicoctl pool add` to change this).

On ubuntu-1

    docker run --publish-service srvF.net4.calico --name workload-F -tid ubuntu

Then get the ipv6 address of workload-F

    docker inspect --format "{{ .NetworkSettings.GlobalIPv6Address }}" workload-F

Note that we have used `ubuntu` instead of `busybox`.  Busybox doesn't support IPv6 versions of network tools like ping.

One ubuntu-2

    docker run --publish-service srvG.net4.calico --name workload-G -tid ubuntu

Then ping workload-F via its ipv6 address that you received above (change the IP address if necessary):

    docker exec workload-G ping6 -c 4 fd80:24e2:f998:72d6::1

[calico-ubuntu-vagrant]: https://github.com/Metaswitch/calico-ubuntu-vagrant
