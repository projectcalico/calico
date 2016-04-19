<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Calico without Docker networking (i.e. `--net=none`)

This tutorial describes how to set up a Calico cluster in a Docker environment
without Docker networking (i.e. --net=none).  With this option, Docker creates
a container with its own network stack, but not to take any steps to configure
its network.  Rather than have Docker configure the network, in this tutorial
we use the `calicoctl` command line tool to add a container into a Calico
network: adding the required interface and routes in to the container, and
configuring Calico with the correct endpoint information.

## 1. Environment setup

To run through the worked example in this tutorial you will to set up two hosts
with a number of installation dependencies.

Follow the instructions in one of the tutorials below to set up a virtualized
environment using Vagrant or a cloud service - be sure to follow the
appropriate instructions for using _Calico without Docker networking_.

- [Vagrant install with CoreOS](../VagrantCoreOS.md)
- [Vagrant install with Ubuntu](../VagrantUbuntu.md)
- [Amazon Web Services (AWS)](../AWS.md)
- [Google Compute Engine (GCE)](../GCE.md)
- [DigitalOcean](../DigitalOcean.md)

Altenatively, you can manually configure your hosts.
- [Manual setup](ManualSetup.md)

If you have everything set up properly you should have `calicoctl` in your
`$PATH`, and two hosts called `calico-01` and `calico-02`.

## 2. Starting Calico services

Once you have your cluster up and running, start calico on all the nodes

On calico-01

    sudo calicoctl node

On calico-02

    sudo calicoctl node

This will start a container on each host. Check they are running

    docker ps

You should see output like this on each node

    vagrant@calico-01:~$ docker ps
    CONTAINER ID        IMAGE                           COMMAND                  CREATED             STATUS              PORTS               NAMES
    ffe6cb403e9b        calico/node:latest              "/sbin/my_init"          21 seconds ago      Up 20 seconds                           calico-node

## 3. Running in the cloud (AWS / DigitalOcean / GCE)

If you are not running in the cloud you may skip this step and jump to step 4.

### 3.1 AWS

If all your endpoints are in the same subnet of your VPC, disable Source/Dest. checks on each instance.  You can disable this with the CLI, or right click the instance in the EC2 console and `Change Source/Dest. Check` from the `Networking` submenu.

Using the AWS CLI installed, for each instance:

    aws ec2 modify-instance-attribute --instance-id <INSTANCE_ID> --source-dest-check "{\"Value\": false}"

After disabling Source/Dest. Checks, configure the `nat-outgoing` option on either Calico node:

    calicoctl pool add 192.168.0.0/16 --nat-outgoing

### 3.2 GCE / DigitalOcean / Other

If you are running in a cloud other than AWS, or your AWS instances are not in the same subnet, you will need to first configure an IP Pool with the `ipip` and `nat-outgoing` options.

On either node:

    calicoctl pool add 192.168.0.0/16 --ipip --nat-outgoing

## 4. Starting containers

Let's go ahead and start a few containers on each host.

On calico-01

    docker run --net=none --name workload-A -tid busybox
    docker run --net=none --name workload-B -tid busybox
    docker run --net=none --name workload-C -tid busybox

On calico-02

    docker run --net=none --name workload-D -tid busybox
    docker run --net=none --name workload-E -tid busybox

## 5. Adding Calico networking

Now that docker is running the containers, we can use `calicoctl` to add
networking to them.

On calico-01

    sudo calicoctl container add workload-A 192.168.0.1
    sudo calicoctl container add workload-B 192.168.0.2
    sudo calicoctl container add workload-C 192.168.0.3

On calico-02

    sudo calicoctl container add workload-D 192.168.0.4
    sudo calicoctl container add workload-E 192.168.0.5

Once the containers have Calico networking added, they gain a new network
interface: the assigned IP address. At this point, the containers have not
been added to any policy profiles so they won't be able to communicate with
any other containers.

Create some profiles (this can be done on either host)

    calicoctl profile add PROF_A_C_E
    calicoctl profile add PROF_B
    calicoctl profile add PROF_D

When each container is added to Calico, an "endpoint" is registered for each
container's interface. Containers are only allowed to communicate with one
another when both of their endpoints are assigned the same profile. To assign
a profile to an endpoint run the following commands.

On calico-01:

    calicoctl container workload-A profile append PROF_A_C_E
    calicoctl container workload-B profile append PROF_B
    calicoctl container workload-C profile append PROF_A_C_E

On calico-02:

    calicoctl container workload-D profile append PROF_D
    calicoctl container workload-E profile append PROF_A_C_E

*Note that whilst the `calicoctl endpoint commands` can be run on any Calico
 node, the `calicoctl container` commands will only work on the Calico node
 where the container is hosted.*


## 6. Validation

By default, profiles are configured so that their members can communicate with
one another, but workloads in other profiles cannot reach them. A, C and E are
all in the same profile so should be able to ping each other.  B and D are in
their own profile so shouldn't be able to ping anyone else.

Now, check that A can ping C (192.168.0.3) and E (192.168.0.5):

    docker exec workload-A ping -c 4 192.168.0.3
    docker exec workload-A ping -c 4 192.168.0.5

Also check that A cannot ping B (192.168.0.2) or D (192.168.0.4):

    docker exec workload-A ping -c 4 192.168.0.2
    docker exec workload-A ping -c 4 192.168.0.4

## IPv6 (Optional)

IPv6 networking is also supported.  If you are using IPv6 address spaces as
well, start your Calico node passing in both the IPv4 and IPv6 addresses of
the host.

For example:

    calicoctl node --ip=172.17.8.101 --ip6=fd80:24e2:f998:72d7::1

See the [IPv6 worked example](IPv6.md) for a worked example.

## Advanced network policy

For details about advanced policy options read the
[Advanced Network Policy tutorial](../../AdvancedNetworkPolicy.md).

## Make a container reachable from the Host-Interface (Internet)

You cannot simply use `-p`on `docker run` to expose ports. We have a working example on how to [expose a container port to the internet](../../ExposePortsToInternet.md)

## Further reading

For details on configuring Calico for different network topologies and to
learn more about Calico under-the-covers please refer to the
[Further Reading](../../../README.md#further-reading) section on the main
documentation README.

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/calico-with-docker/without-docker-networking/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
