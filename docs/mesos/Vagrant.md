<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Vagrant Deployed Mesos Cluster with Calico
This guide will start a running Mesos cluster (master and two agents) with Calico Networking using a simple `vagrant up`.

These machines are flexible and will allow you to use either the
Docker Containerizer or the Unified Containerizer for launching tasks.

## Prerequisites
This guide requires a host machine with:

 * [VirtualBox][virtualbox] to host the virtual machines.
 * [Vagrant][vagrant] to install and configure the machines in Virtual Box.
 * [Git][git]

## Getting Started
1. First, clone this repository and change to the Mesos vagrant directory:

  ```
  git clone https://github.com/projectcalico/calico-containers.git
  cd calico-containers/docs/mesos/vagrant-centos
  ```

2. Then launch the Vagrant demo:
  ```
  vagrant up
  ```

That's it! Your Mesos Cluster is ready to use!

## Log in to Vagrant machines

To connect to your servers:

#### Linux/Mac OS X
Run:

	vagrant ssh <hostname>

#### Windows
Follow instructions from https://github.com/nickryand/vagrant-multi-putty.

Then, run:

	vagrant putty <hostname>

## Next steps

With your cluster deployed, you have everything in place to run the
[Calico Mesos Stars Demo](stars-demo/README.md), an interesting network
policy visualizer demo that shows how Calico can secure your cluster.
(Note that this demo is currently worked specifically for use with the
Docker Containerizer.)

Alternatively, you can follow one of our usage guides to learn how to
launch Calico-networked tasks with either the [Docker Containerizer]
(./UsageGuideDockerContainerizer.md) or the [Unified Containerizer]
(UsageGuideUnifiedContainerizer.md).

## Virtual Machines Info

The installed virtual machines will be running with the following config:

```
.-----------------------------------------------------------------------------------.
| Machine Type | OS     | Hostname        | IP Address     | Services               |
|--------------|--------|-----------------|----------------|------------------------|
| Master       | Centos | calico-mesos-01 | 172.24.197.101 | mesos-master           |
|              |        |                 |                | etcd                   |
|              |        |                 |                | docker                 |
|              |        |                 |                | zookeeper              |
|              |        |                 |                | marathon               |
|              |        |                 |                | marathon load-balancer |
|              |        |                 |                | calico-node            |
|              |        |                 |                | calico-libnetwork      |
|--------------|--------|-----------------|----------------|------------------------|
| Agents       | Centos | calico-mesos-02 | 172.24.197.102 | mesos-agent            |
|              |        | calico-mesos-03 | 172.24.197.103 | docker                 |
|              |        |                 |                | calico-node            |
|              |        |                 |                | calico-libnetwork      |
'-----------------------------------------------------------------------------------'
```

Note that Calico is installed on the Agents so that tasks are automatically
networked by Calico.  Calico is also run on the Master to allow Marathon-lb
to route external requests to tasks with Calico IPs

## Adding More Agents (Optional)
You can modify the script to use multiple agents. To do this, modify the `num_instances`
variable in the `Vagrantfile`.  The variable is set to `3`, where the first machine is the
master and every other machine is an agent.  If you'd like four agents, set `num_instances`
to be `5`.

Every agent instance will take similar form to the agent instances in the table above.

The `hostname` and `IP address` of the machines are generated in the vagrant script,
so additional machines will take these values in the form:

	Hostname:   `calico-mesos-0X`
	IP address: `172.24.197.10X`

where `X` is the instance number.

If you've already run the vagrant script but want to add more Agents, just
change the `num_instances` variable then run `vagrant up` again.  Your
existing VMs will remain installed and ready.

[virtualbox]: https://www.virtualbox.org/
[vagrant]: https://www.vagrantup.com/
[git]: https://www.git-scm.com/
[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/mesos/Vagrant.md?pixel)](https://github.com/igrigorik/ga-beacon)
