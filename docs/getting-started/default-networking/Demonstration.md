<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.12.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Calico with Docker default networking

This demonstration uses Docker's standard networking infrastructure, requiring you to explicitly add a created container into a Calico network.

## Environment
This demonstration makes some assumptions about the environment you have.
See [Environment Setup](EnvironmentSetup.md) for instructions on getting an 
appropriate environment.

If you have everything set up properly you should have `calicoctl` in your 
`$PATH`, and two hosts called `calico-01` and `calico-02`.


## Running in the cloud (AWS / DigitalOcean / GCE)

If you are running in the cloud, you will need to configure an IP Pool with
the `ipip` and `nat-outgoing` options.

On either node:

    calicoctl pool add 192.168.0.0/16 --ipip --nat-outgoing


## Starting Calico services<a id="calico-services"></a>

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

## Networking containers.

### Starting containers
Let's go ahead and start a few containers on each host.

On calico-01

    docker run --net=none --name workload-A -tid busybox
    docker run --net=none --name workload-B -tid busybox
    docker run --net=none --name workload-C -tid busybox

On calico-02

    docker run --net=none --name workload-D -tid busybox
    docker run --net=none --name workload-E -tid busybox

### Adding Calico networking
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


### Testing it
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

See the [IPv6 demonstration](DemonstrationIPv6.md) for a worked example.
[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/getting-started/default-networking/Demonstration.md?pixel)](https://github.com/igrigorik/ga-beacon)
