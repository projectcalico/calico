<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.14.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Manually Deploying a Dockerized Mesos Cluster with Calico

In these instructions, we will run a Mesos Cluster where all cluster services run as Docker containers.  This speeds deployment and will prevent pesky issues like incompatible dependencies.  The services we will need are:

 * Zookeeper
 * etcd
 * Mesos Master
 * Mesos Agent
 * Calico
 * Marathon (Mesos framework)

We'll concentrate on getting Mesos and Calico up and running as quickly as possible.  This means leaving out the details of how to configure highly-available services.  Instead, we'll install Zookeeper, etcd, and the Mesos Master on the same "master" node.

**For an automated install of a two-host Dockerized Mesos cluster using Vagrant and VirtualBox, follow the [Vagrant Dockerized Mesos Guide](DockerizedVagrant.md).**


# Preparation

These instructions are designed to run on CentOS/Red Hat Enterprise Linux 7 but, other than the initial commands to configure Docker, should work on any Linux distribution that supports Docker 1.7+ and `systemd`.

If your distribution does not support `systemd`, you will need to create initialization files for each of the services.  These should be straightforward based on the included `.service` files, but talk to us on the [Calico Users' Slack](https://calicousers-slackin.herokuapp.com/) if you want some assistance.  If you write init files for a new system, share the love!  PRs are welcome :) 

## Install Docker

    sudo yum install docker docker-selinux
    sudo systemctl enable docker.service
    sudo systemctl start docker.service

## Verify Docker installation

    sudo docker run hello-world

*Optional:* You may also want to create a `docker` group and add your local user to the group.  This means you can drop the `sudo` in the `docker ...` commands that follow.

    sudo groupadd docker
    sudo usermod -aG docker `whoami`
    sudo systemctl restart docker.service

Then log out (`exit`) and log back in to pick up your new group association.  Verify your user has access to Docker without sudo

    docker ps

## Set & verify fully qualified domain name.

These instructions assume each host can reach other hosts using their fully qualified domain names (FQDN).  To check the FQDN on a host use

    hostname -f

Then attempt to ping that name from other servers.

Also important are that Calico and Mesos have the same view of the (non-fully-qualified) hostname.  In particular, the value returned by

    hostname

must be unique for each node in your cluster.  Both Calico and Mesos use this value to identify the host.

## Configure your firewall

You will either need to configure the firewalls on each node in your cluster (recommended) to allow access to the cluster services or disable it completely.  Included in this section is configuration examples for `firewalld`.  If you use a different firewall, check your documentation for how to open the listed ports.

Master node(s) require

| Service Name | Port/protocol     |
|--------------|-------------------|
| zookeeper    | 2181/tcp          |
| mesos-master | 5050/tcp          |
| etcd         | 2379/tcp 4001/tcp |
| marathon     | 8080/tcp          |

Example `firewalld` config

    sudo firewall-cmd --zone=public --add-port=2181/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=5050/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=2379/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=4001/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent
    sudo systemctl restart firewalld

Agent (compute) nodes require

| Service Name | Port/protocol     |
|--------------|-------------------|
| BIRD (BGP)   | 179/tcp           |
| mesos-agent  | 5051/tcp          |

Example `firewalld` config

    sudo firewall-cmd --zone=public --add-port=179/tcp --permanent
    sudo firewall-cmd --zone=public --add-port=5051/tcp --permanent
    sudo systemctl restart firewalld

# Set up Master services.

Pull the Docker images.  This will take a few minutes.

    sudo docker pull jplock/zookeeper:3.4.5
    sudo docker pull quay.io/coreos/etcd:v2.2.0
    sudo docker pull calico/mesos-calico
    sudo docker pull mesosphere/marathon:v0.9.1
    sudo docker pull calico/node:v0.8.0

Next, download the unit files

    wget https://github.com/projectcalico/calico-mesos/releases/download/v0.1.2/units.tgz
    tar -xzf units.tgz

## Zookeeper

We'll use systemd to keep Zookeeper running.  Copy the unit into `/usr/lib/systemd/system/`.  This unit file starts a Docker container running Zookeeper.

    sudo cp zookeeper.service /usr/lib/systemd/system/
    sudo systemctl enable zookeeper.service
    sudo systemctl start zookeeper.service

## Mesos Master

Before running the Master node, be sure to set the IP address of the Master to connect to the Mesos cluster.  Run the following command, replacing `<MASTER_IP>` with the Master's IP address.

    sudo sh -c 'echo IP=<MASTER_IP> > /etc/sysconfig/mesos-master'

Create and enable the `mesos-master` unit, which starts a Docker container running Mesos.

    sudo cp mesos-master.service /usr/lib/systemd/system/
    sudo systemctl enable mesos-master.service
    sudo systemctl start mesos-master.service

## Etcd

`etcd` needs your fully qualified domain name to start correctly.  The included
unit file looks for this value in `/etc/sysconfig/etcd`.

    sudo sh -c 'echo FQDN=`hostname -f` > /etc/sysconfig/etcd'
    sudo cp etcd.service /usr/lib/systemd/system/
    sudo systemctl enable etcd.service
    sudo systemctl start etcd.service

## Marathon

Lastly, start Marathon, a Mesos framework you can use to start arbitrary tasks on your cluster.

    sudo cp marathon.service /usr/lib/systemd/system/
    sudo systemctl enable marathon.service
    sudo systemctl start marathon.service

# Set up Agent Services

Do this for each compute host you'll use in your Mesos cluster.

Pull the Docker images.  This will take a few minutes.

    sudo docker pull calico/mesos-calico
    sudo docker pull calico/node:v0.8.0

Next, download the unit files

    wget https://github.com/projectcalico/calico-mesos/releases/download/v0.1.2/units.tgz
    tar -xzf units.tgz

## Calico

`calicoctl` is a small CLI tool to control your Calico network.  It's used to start Calico services on your compute host, as well as inspect and modify Calico configuration.

    curl -L -O https://github.com/projectcalico/calico-containers/releases/download/v0.8.0/calicoctl
    chmod +x calicoctl
    sudo cp calicoctl /usr/bin/

You can learn more about `calicoctl` by running `calicoctl --help`.

You'll need to configure Calico with the correct location of the etcd service.  In the following line, replace `<MASTER_IP>` with the IP address of the Master node.

    sudo sh -c 'echo ETCD_AUTHORITY=<MASTER_IP>:4001 > /etc/sysconfig/calico'

Then, enable the Calico service via `systemd`

    sudo cp calico.service /usr/lib/systemd/system/
    sudo systemctl enable calico.service
    sudo systemctl start calico.service

Verify Calico is running

    calicoctl status

## Mesos Agent

Use the following commands to tell the Mesos Agent where to find Zookeeper.  The Mesos Agent uses Zookeeper to keep track of the current Mesos Master.  We installed it on the same host as the Mesos Master earlier, so substitute the name or IP of that host for `<ZOOKEEPER_IP>`:

    sudo sh -c 'echo ZK=<ZOKEEPER_IP> > /etc/sysconfig/mesos-agent'

You also need to specify the IP address of the Agent to connect to the Mesos cluster.  Run the following command, replacing `<AGENT_IP>` with the Agent's IP address.

    sudo sh -c 'echo IP=<AGENT_IP> >> /etc/sysconfig/mesos-agent'

Then, enable the Mesos Agent service

    sudo cp mesos-agent.service /usr/lib/systemd/system/
    sudo systemctl enable mesos-agent.service
    sudo systemctl start mesos-agent.service

# Test your cluster

To ensure that your cluster is properly networking containers with Calico and enforcing policy as expected, run the Calico Mesos Test Framework, which launches various tasks across your Mesos cluster:
```
docker run calico/calico-mesos-framework 172.18.8.101:5050
```
> NOTE: Some tests require multiple hosts to ensure cross-host communication, and may fail unless you are running 2+ agents.

Additionally, you can launch your own tasks using Marathon. See our [Marathon Task Launch Instructions](README.md#3-launching-tasks) for more information.

[calico]: http://projectcalico.org
[mesos]: https://mesos.apache.org/
[net-modules]: https://github.com/mesosphere/net-modules
[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/mesos/DockerizedDeployment.md?pixel)](https://github.com/igrigorik/ga-beacon)
