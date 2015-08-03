# Calico with Docker default networking

This demonstration uses Dockers standard networking infrastructure, requiring you to explicitly add a created container into a Calico network.

## Environment
This demonstration makes some assumptions about the environment you have.
See [Environment Setup](EnvironmentSetup.md) for instructions on getting an 
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
    39de206f7499        calico/node:v0.5.3   "/sbin/my_init"        2 minutes ago       Up 2 minutes                                                         calico-node

## Networking containers.

### Starting containers
Let's go ahead and start a few of containers on each host.

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
interface the the assigned IP address. At this point, the containers have not 
been added to any policy profiles so they won't be able to communicate with 
any other containers.

Create some profiles (this can be done on either host)

    calicoctl profile add PROF_A_C_E
    calicoctl profile add PROF_B
    calicoctl profile add PROF_D

When each container is added to calico, an "endpoint" is registered for each 
container's interface. Containers are only allowed to communicate with one 
another when both of their endpoints are assigned the same profile. To assign 
a profile to an endpoint, we will first get the endpoint's ID with 
`calicoctl container <CONTAINER> endpoint-id show`, then paste it into the 
`calicoctl endpoint <ENDPOINT_ID> profile append [<PROFILES>]`  command.

On core-01:

    
    calicoctl endpoint $(calicoctl container workload-A endpoint-id show) profile append PROF_A_C_E
    calicoctl endpoint $(calicoctl container workload-B endpoint-id show) profile append PROF_B
    calicoctl endpoint $(calicoctl container workload-C endpoint-id show) profile append PROF_A_C_E

On core-02:

    calicoctl endpoint $(calicoctl container workload-D endpoint-id show) profile append PROF_D
    calicoctl endpoint $(calicoctl container workload-E endpoint-id show) profile append PROF_A_C_E

*Note that whilst the `calicoctl endpoint commands` can be run on any Calico 
 node, the `calicoctl container` commands will only work on the Calico node 
 where the container is hosted.  Therefore the combined commands above must
 be run on specific nodes.*


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
