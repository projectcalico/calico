# Calico with Powerstrip
This demonstration uses [Powerstrip](https://github.com/ClusterHQ/powerstrip), a pluggable HTTP proxy for the Docker API. Development of the Powerstrip version of Calico is lagging behind the master branch, so an older version of calicoctl and the calico-node docker image are required.

## Environment
This demonstration makes some assumptions about the environment you have. See 
[Environment Setup](EnvironmentSetup.md) for instructions on getting an 
appropriate environment.

If you have everything set up properly you should have `calicoctl` in your
`$PATH`, and two hosts called `calico-01` and `calico-02`.

## Starting Calico services<a id="calico-services"></a>

Once you have your cluster up and running, start calico on both nodes.

On both calico-01 and calico-02:

    sudo calicoctl node --ip=`ip route get 8.8.8.8 | head -1 | cut -d' ' -f8`


This command starts a Calico container.  The `--ip` parameter here calls a command that gets the ip address of your host regardless of the Calico environment you have set up.

After running the command on each host, check the containers are running:

    docker ps

You should see output like this on each node

    vagrant@calico-01:~$ docker ps -a
    CONTAINER ID        IMAGE                    COMMAND                CREATED             STATUS              PORTS                                            NAMES
    39de206f7499        calico/node:v0.4.9   "/sbin/my_init"        2 minutes ago       Up 2 minutes                                                         calico-node

## Routing via Powerstrip

To allow Calico to set up networking automatically during container creation, 
Docker API calls need to be routed through the `Powerstrip` proxy which is 
running on port `2377` on each node. The easiest way to do this is to set the 
environment before running docker commands.  

On both hosts run

    export DOCKER_HOST=localhost:2377

(Note - this export will only persist for your current SSH session)

Later, once you have guest containers and you want to attach to them or to 
execute a specific command in them, you'll probably need to skip the 
Powerstrip proxying, such that the `docker attach` or `docker exec` command 
speaks directly to the Docker daemon; otherwise standard input and output 
don't flow cleanly to and from the container. To do that, just prefix the 
individual relevant command with `DOCKER_HOST=localhost:2375`.

For example, `docker attach` commands should be:

    DOCKER_HOST=localhost:2375 docker attach node1

Also, when attaching, remember to hit Enter a few times to get a prompt to use 
`Ctrl-P,Q` rather than `exit` to back out of a container but still leave it 
running.

## Creating networked endpoints

Now you can start any other containers that you want within the cluster, using 
normal Docker commands. To get Calico to network them, simply add 
`-e CALICO_IP=<IP address>` to specify the IP address that you want that 
container to have.

(By default containers need to be assigned IPs in the `192.168.0.0/16` range. 
Use `calicoctl` commands to set up different ranges if desired)

So let's go ahead and start a few of containers on each host.

On core-01

    docker run -e CALICO_IP=192.168.1.1 --name workload-A -tid busybox
    docker run -e CALICO_IP=192.168.1.2 --name workload-B -tid busybox
    docker run -e CALICO_IP=192.168.1.3 --name workload-C -tid busybox

On core-02

    docker run -e CALICO_IP=192.168.1.4 --name workload-D -tid busybox
    docker run -e CALICO_IP=192.168.1.5 --name workload-E -tid busybox

At this point, the containers have not been added to any policy profiles so 
they won't be able to communicate with any other containers.

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

*Note that creating a new profile with `calicoctl profile add` will work on 
any Calico node, but assigning an endpoint a profile with 
`calicoctl endpoint <ENDPOINT_ID> profile append` will only work on the Calico 
node where the container is hosted.*

Now, check that A can ping C (192.168.1.3) and E (192.168.1.5):

    docker exec workload-A ping -c 4 192.168.1.3
    docker exec workload-A ping -c 4 192.168.1.5

Also check that A cannot ping B (192.168.1.2) or D (192.168.1.4):

    docker exec workload-A ping -c 4 192.168.1.2
    docker exec workload-A ping -c 4 192.168.1.4

By default, profiles are configured so that their members can communicate with 
one another, but workloads in other profiles cannot reach them.  B and D are 
in their own profiles so shouldn't be able to ping anyone else.

## Streamlining Container Creation

In addition to the step by step approach above you can have Calico assign IP 
addresses automatically using `CALICO_IP=auto` and specify the profile at 
creation time using `CALICO_PROFILE=<profile name>`.  (The profile will be 
created automatically if it does not already exist.)

On core-01

    docker run -e CALICO_IP=auto -e CALICO_PROFILE=PROF_A_C_E --name workload-F -tid busybox
    docker exec workload-A ping -c 4 192.168.1.6
