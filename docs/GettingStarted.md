# Getting started with Calico on Docker

Calico provides IP connectivity between Docker containers on different hosts (as well as on the same host).

*In order to run this example you will need a 2-node Linux cluster with Docker and etcd installed and running.*  You can do one of the following.
* Set this up yourself, following these instructions: [Manual Cluster Setup](./ManualClusterSetup.md)
* Use [Calico CoreOS Vagrant][calico-coreos-vagrant] to start a cluster in VMs on your laptop or workstation.

If you want to get started quickly and easily then we recommend just using Vagrant.

If you have difficulty, try the [Troubleshooting Guide](./Troubleshooting.md).

### A note about names & addresses
In this example, we will use the server names and IP addresses from the [Calico CoreOS Vagrant][calico-coreos-vagrant] example.

| hostname | IP address   |
|----------|--------------|
| core-01  | 172.17.8.101 |
| core-02  | 172.17.8.102 |

If you set up your own cluster, substitute the hostnames and IP addresses assigned to your servers.

## Starting Calico services<a id="calico-services"></a>

Once you have your cluster up and running, start calico on all the nodes

On core-01

    sudo ./calicoctl node --ip=172.17.8.101

On core-02

    sudo ./calicoctl node --ip=172.17.8.102

This will start a container. Check they are running

    sudo docker ps

You should see output like this on each node

    core@core-01 ~ $ docker ps
    CONTAINER ID        IMAGE                      COMMAND                CREATED             STATUS              PORTS               NAMES
    077ceae44fe3        calico/node:v0.4.2     "/sbin/my_init"     About a minute ago   Up About a minute                       calico-node

## Routing via Powerstrip

To allow Calico to set up networking automatically during container creation, Docker API calls need to be routed through the `Powerstrip` proxy which is running on port `2377` on each node. The easiest way to do this is to set the environment before running docker commands.

On both hosts run

    export DOCKER_HOST=localhost:2377

(Note - this export will only persist for your current SSH session)

Later, once you have guest containers and you want to attach to them or to execute a specific command in them, you'll probably need to skip the Powerstrip proxying, such that the `docker attach` or `docker exec` command speaks directly to the Docker daemon; otherwise standard input and output don't flow cleanly to and from the container. To do that, just prefix the individual relevant command with `DOCKER_HOST=localhost:2375`.

For example, `docker attach` commands should be:

    DOCKER_HOST=localhost:2375 docker attach node1

Also, when attaching, remember to hit Enter a few times to get a prompt to use `Ctrl-P,Q` rather than `exit` to back out of a container but still leave it running.

## Creating networked endpoints

Now you can start any other containers that you want within the cluster, using normal docker commands. To get Calico to network them, simply add `-e CALICO_IP=<IP address>` to specify the IP address that you want that container to have.

(By default containers need to be assigned IPs in the `192.168.0.0/16` range. Use `calicoctl` commands to set up different ranges if desired)

So let's go ahead and start a few of containers on each host.

On core-01

    docker run -e CALICO_IP=192.168.1.1 --name workload-A -tid busybox
    docker run -e CALICO_IP=192.168.1.2 --name workload-B -tid busybox
    docker run -e CALICO_IP=192.168.1.3 --name workload-C -tid busybox

On core-02

    docker run -e CALICO_IP=192.168.1.4 --name workload-D -tid busybox
    docker run -e CALICO_IP=192.168.1.5 --name workload-E -tid busybox

At this point, the containers have not been added to any policy profiles so they won't be able to communicate with any other containers.

Create some profiles (this can be done on either host)

    ./calicoctl profile add PROF_A_C_E
    ./calicoctl profile add PROF_B
    ./calicoctl profile add PROF_D

Now add the containers to the profile (note that `profile add` works from any Calico node, but `profile <PROFILE> member add` only works from the Calico node where the container is hosted).

On core-01:

    ./calicoctl profile PROF_A_C_E member add workload-A
    ./calicoctl profile PROF_B member add workload-B
    ./calicoctl profile PROF_A_C_E member add workload-C

On core-02:

    ./calicoctl profile PROF_D member add workload-D
    ./calicoctl profile PROF_A_C_E member add workload-E

Now, check that A can ping C (192.168.1.3) and E (192.168.1.5):

    docker exec workload-A ping -c 4 192.168.1.3
    docker exec workload-A ping -c 4 192.168.1.5

Also check that A cannot ping B (192.168.1.2) or D (192.168.1.4):

    docker exec workload-A ping -c 4 192.168.1.2
    docker exec workload-A ping -c 4 192.168.1.4

By default, profiles are configured so that their members can communicate with one another, but workloads in other profiles cannot reach them.  B and D are in their own profiles so shouldn't be able to ping anyone else.

Finally, to clean everything up (without doing a `vagrant destroy`), you can run

    sudo ./calicoctl reset


## IPv6
To connect your containers with IPv6, first make sure your Docker hosts each have an IPv6 address assigned.

On core-01

    sudo ip addr add fd80:24e2:f998:72d6::1/112 dev eth1

On core-02

    sudo ip addr add fd80:24e2:f998:72d6::2/112 dev eth1

Verify connectivity by pinging.

On core-01

    ping6 fd80:24e2:f998:72d6::2

Then restart your calico-node processes with the `--ip6` parameter to enable v6 routing.

On core-01

    sudo ./calicoctl node --ip=172.17.8.101 --ip6=fd80:24e2:f998:72d6::1

On core-02

    sudo ./calicoctl node --ip=172.17.8.102 --ip6=fd80:24e2:f998:72d6::2

Then, you can start containers with IPv6 connectivity by giving them an IPv6 address in `CALICO_IP`. By default, Calico is configured to use IPv6 addresses in the pool fd80:24e2:f998:72d6/64 (`calicoctl ipv6 pool add` to change this).

On core-01

    docker run -e CALICO_IP=fd80:24e2:f998:72d6::1:1 --name workload-F -tid phusion/baseimage:0.9.16
    ./calicoctl profile add PROF_F_G
    ./calicoctl profile PROF_F_G member add workload-F

Note that we have used `phusion/baseimage:0.9.16` instead of `busybox`.  Busybox doesn't support IPv6 versions of network tools like ping.  Baseimage was chosen since it is the base for the Calico service images, and thus won't require an additional download, but of course you can use whatever image you'd like.

One core-02

    docker run -e CALICO_IP=fd80:24e2:f998:72d6::1:2 --name workload-G -tid phusion/baseimage:0.9.16
    ./calicoctl profile PROF_F_G member add workload-G
    docker exec workload-G ping6 -c 4 fd80:24e2:f998:72d6::1:1

[calico-coreos-vagrant]: https://github.com/Metaswitch/calico-coreos-vagrant-example
