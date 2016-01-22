<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.14.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Deploying a Vagrant Dockerized Mesos Cluster with Calico

In these instructions, we will create two Centos virtual machines (a master and an agent) that run all cluster services as Docker containers.  This speeds deployment and will prevent pesky issues like incompatible dependencies.

If you would prefer to run the commands manually to better understand what is being run in the script,
check out the [Manual Dockerized Deployment guide](DockerizedDeployment.md).

On the Master machine, the script installs containers for:

 * Zookeeper
 * etcd
 * Mesos Master
 * Marathon (Mesos framework)

On the Agent machine, we will install containers for:

 * Mesos Agent
 * Calico

## Requirements

To run these instructions, you will need a host machine with:

 * [VirtualBox][virtualbox] to host the Mesos master and slave virtual machines
 * [Vagrant][vagrant] to run the script that provisions the Virtual Machines
 * 4+ GB memory
 * 2+ CPU
 * 80 GB available storage space (40 GB per machine)


## Deploy Mesos Cluster with Vagrant

To get the vagrant script, you must clone the [`calico-mesos repository`][calico-mesos] onto your host.

```
# HTTPS
git clone https://github.com/projectcalico/calico-mesos.git
```

Change into the cloned `calico-mesos` directory, then run `vagrant up` to execute the `Vagrantfile` in this directory:

```
cd calico-mesos
vagrant up
```

That's it!  Note that the script may take up to 30 minutes to complete as it creates the two
virtual machines and pulls the docker container images, so don't be alarmed if it 
seems to be taking its time.

## Vagrant Install Results

Once the vagrant install is finished, you will have two machines running Docker with the following setup:

### Master

 * **OS**: `Centos`
 * **Hostname**: `calico-01`
 * **IP**: `172.18.8.101`
 * **Docker Containers**:
	 * `mesos-master` - `calico/mesos-calico` 
	 * `etcd` - `quay.io/coreos/etcd`
	 * `zookeeper` - `jplock/zookeeper`
	 * `marathon` - `mesosphere/marathon`

### Agent

 * **OS**: `Centos`
 * **Hostname**: `calico-02`
 * **IP**: `172.18.8.102`
 * **Docker Containers**:
	 * `mesos-agent` - `calico/mesos-calico`
	 * `calico-node` - `calico/node`

You can log into each machine by running:
```
vagrant ssh <HOSTNAME>
```

## Next steps

### Use Frameworks 

At this point, you're Mesos Cluster is configured and you can start using frameworks.

To ensure that your cluster is properly networking containers with Calico and enforcing policy as expected, run the Calico Mesos Test Framework, which launches various tasks across your Mesos cluster:
```
docker run calico/calico-mesos-framework 172.18.8.101:5050
```
> NOTE: Some tests require multiple hosts to ensure cross-host communication, and may fail unless you are running 2+ agents.

Additionally, you can launch your own tasks using Marathon. See our [Marathon Task Launch Instructions](README.md#3-launching-tasks) for more information.

### More Agents

You can modify the script to use multiple agents. To do this, modify the `num_instances` variable
in the `Vagrantfile` to be greater than `2`.  The first instance created is the master instance, every 
additional instance will be an agent instance.

Every agent instance will take similar form to the agent instance above:

 * **OS**: `Centos`
 * **Hostname**: `calico-0X`
 * **IP**: `172.18.8.10X`
 * **Docker Containers**:
	 * `mesos-agent` - `calico/mesos-calico`
	 * `calico-node` - `calico/node`

where `X` is the instance number.
 
Each agent instance will require additional storage and memory resources.

[calico-mesos]: https://github.com/projectcalico/calico-mesos
[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/
[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/mesos/DockerizedVagrant.md?pixel)](https://github.com/igrigorik/ga-beacon)
