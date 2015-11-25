# Deploying a Dockerized Mesos Cluster with Calico.

In these instructions, we will run all cluster services as [Docker][docker] containers.  This speeds deployment and will prevent pesky issues like incompatible dependencies.  The services we will need are

 * Zookeeper
 * etcd
 * Mesos Master
 * Mesos Agent
 * Calico
 * Marathon (Mesos framework)

In these brief instructions, I'll concentrate on getting Mesos and Calico up and running as quickly as possible.  This means leaving out the details of how to configure highly-available services.  Instead, I'll install Zookeeper, etcd, and the Mesos Master on the same "master" node.


# Preparation

These instructions are designed to run on CentOS/Red Hat Enterprise Linux 7 but, other than the initial commands to configure Docker, should work on any Linux distribution that supports Docker 1.7+ and `systemd`.

If your distribution does not support `systemd`, you will need to create initialization files for each of the services.  These should be straightforward based on the included `.service` files, but talk to us on the [Calico Users' Slack](https://calicousers-slackin.herokuapp.com/) if you want some assistance.  If you write init files for a new system, share the love!  PRs are welcome :) 

## Install Docker

    $ sudo yum install docker docker-selinux
    $ sudo systemctl enable docker.service
    $ sudo systemctl start docker.service

## Verify Docker installation

    $ sudo docker run hello-world

*Optional:* You may also want to create a `docker` group and add your local user to the group.  This means you can drop the `sudo` in the `docker ...` commands that follow.

    $ sudo groupadd docker
    $ sudo usermod -aG docker `whoami`
    $ sudo systemctl restart docker.service

Then log out (`exit`) and log back in to pick up your new group association.  Verify your user has access to Docker without sudo

    $ docker ps

## Set & verify fully qualified domain name.

These instructions assume each host can reach other hosts using their fully qualified domain names (FQDN).  To check the FQDN on a host use

    $ hostname -f

Then attempt to ping that name from other servers.

Also important are that Calico and Mesos have the same view of the (non-fully-qualified) hostname.  In particular, the value returned by

    $ hostname

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

    $ sudo firewall-cmd --zone=public --add-port=2181/tcp --permanent
    $ sudo firewall-cmd --zone=public --add-port=5050/tcp --permanent
    $ sudo firewall-cmd --zone=public --add-port=2379/tcp --permanent
    $ sudo firewall-cmd --zone=public --add-port=4001/tcp --permanent
    $ sudo firewall-cmd --zone=public --add-port=8080/tcp --permanent
    $ sudo systemctl restart firewalld

Agent (compute) nodes require

| Service Name | Port/protocol     |
|--------------|-------------------|
| BIRD (BGP)   | 179/tcp           |
| mesos-agent  | 5051/tcp          |

Example `firewalld` config

    $ sudo firewall-cmd --zone=public --add-port=179/tcp --permanent
    $ sudo firewall-cmd --zone=public --add-port=5051/tcp --permanent
    $ sudo systemctl restart firewalld

# Set up Master services.

Pull the Docker images.  This will take a few minutes.

    $ sudo docker pull jplock/zookeeper:3.4.5
    $ sudo docker pull quay.io/coreos/etcd:v2.2.0
    $ sudo docker pull calico/mesos-calico
    $ sudo docker pull mesosphere/marathon:v0.9.1
    $ sudo docker pull calico/node:v0.8.0

Next, download the unit files

    $ wget https://github.com/projectcalico/calico-mesos/releases/download/v0.1.2/units.tgz
    $ tar -xzf units.tgz

## Zookeeper

We'll use systemd to keep Zookeeper running.  Copy the unit into `/usr/lib/systemd/system/`.  This unit file starts a Docker container running Zookeeper.

    $ sudo cp zookeeper.service /usr/lib/systemd/system/
    $ sudo systemctl enable zookeeper.service
    $ sudo systemctl start zookeeper.service

## Mesos Master

Create and enable the `mesos-master` unit, which starts a Docker container running Mesos.

    $ sudo cp mesos-master.service /usr/lib/systemd/system/
    $ sudo systemctl enable mesos-master.service
    $ sudo systemctl start mesos-master.service

## Etcd

`etcd` needs your fully qualified domain name to start correctly.  The included
unit file looks for this value in `/etc/sysconfig/etcd`.

    $ sudo sh -c 'echo FQDN=`hostname -f` > /etc/sysconfig/etcd'
    $ sudo cp etcd.service /usr/lib/systemd/system/
    $ sudo systemctl enable etcd.service
    $ sudo systemctl start etcd.service

## Marathon

Lastly, start Marathon, a Mesos framework you can use to start arbitrary tasks on your cluster.

    $ sudo cp marathon.service /usr/lib/systemd/system/
    $ sudo systemctl enable marathon.service
    $ sudo systemctl start marathon.service

# Set up Agent Services

Do this for each compute host you'll use in your Mesos cluster.

Pull the Docker images.  This will take a few minutes.

    $ sudo docker pull calico/mesos-calico
    $ sudo docker pull calico/node:v0.8.0

Next, download the unit files

    $ wget https://github.com/projectcalico/calico-mesos/releases/download/v0.1.2/units.tgz
    $ tar -xzf units.tgz

## Calico

`calicoctl` is a small CLI tool to control your Calico network.  It's used to start Calico services on your compute host, as well as inspect and modify Calico configuration.

    $ curl -L -O https://github.com/projectcalico/calico-docker/releases/download/v0.8.0/calicoctl
    $ chmod +x calicoctl
    $ sudo cp calicoctl /usr/bin/

You can learn more about `calicoctl` by running `calicoctl --help`.

You'll need to configure Calico with the correct location of the etcd service.  In the following line, replace `masterip` with the IP address of the Master node.

    $ sudo sh -c 'echo ETCD_AUTHORITY=masterip:4001 > /etc/sysconfig/calico'

Then, enable the Calico service via `systemd`

    $ sudo cp calico.service /usr/lib/systemd/system/
    $ sudo systemctl enable calico.service
    $ sudo systemctl start calico.service

Verify Calico is running

    $ calicoctl status

## Mesos Agent

The Mesos Agent uses Zookeeper to keep track of the current Mesos Master.  Use the following command to tell the Mesos Agent where to find Zookeeper.  We installed it on the same host as the Mesos Master earlier, so substitute the name or IP of that host for `zookeeperip`.

    $ sudo sh -c 'echo ZK=zookeeperip > /etc/sysconfig/mesos-agent'

Then, enable the Mesos Agent service

    $ sudo cp mesos-agent.service /usr/lib/systemd/system/
    $ sudo systemctl enable mesos-agent.service
    $ sudo systemctl start mesos-agent.service

# Test your cluster

Verify Mesos is working and has the expected number of agents (what used to be called /slaves/ and still are in the UI).  Point your browser to the master node, port 5050 (e.g. http://mesos-master.mydomain:5050/ ).

Verify that Marathon is up and available on port 8080 (e.g. http://mesos-master.mydomain:8080/ ).

Test Calico network functionality by running our test framework.  On the master node

    $ sudo docker exec -ti mesos-master bash

This will start a new shell inside the `mesos-master` container.

    $ cd /framework
    $ python calico_framework.py

The Calico framework launches a series of tasks on your Mesos cluster to verify network connectivity and network isolation are working correctly.

At time of writing Marathon still uses the old Mesos networking, rather than Calico IP-per-container networking.  We still include it so you can test backward compatibility.  Try launching some tasks.

[calico]: http://projectcalico.org
[mesos]: https://mesos.apache.org/
[net-modules]: https://github.com/mesosphere/net-modules
[docker]: https://www.docker.com/
