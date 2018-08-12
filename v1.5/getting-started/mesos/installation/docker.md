---
title: Installing Calico for the Docker Containerizer
sitemap: false 
---

This document provides the commands to download and run Calico
for use with the Docker Containerizer in Mesos.

## Prerequisite: Docker
Calico networks Docker tasks for Mesos with its libnetwork plugin. In order to
run the libnetwork plugin, the Docker daemon on each agent must be configured
with a cluster store.

If using etcd as a cluster store, for example, run the Docker daemon with the
following additional parameter:

```shell
    --cluster-store=etcd://<ETCD HOST>:<PORT>
```

Replacing `<ETCD HOST>:<PORT>` with the appropriate `hostname:port`
for your etcd cluster.

## Install and Run Calico
It is very easy to install Calico to use with the
Docker Containerizer.

1. On each Mesos Agents, download the `calicoctl` command-line tool:

```shell
curl -o /usr/bin/calicoctl -L https://github.com/projectcalico/calico-containers/releases/download/v0.22.0/calicoctl
chmod a+x calicoctl
```

2. Launch the `calico/node` and `calico/node-libnetwork` containers.

For production deployments, we recommend running the two
containers as services. Visit our guide on [running Calico
as a Service]({{site.baseurl}}/{{page.version}}/usage/configuration/as-service) to learn how to do this.

For test environments that you would like to get up and running
quickly, you can launch the container with `calicoctl`:

```shell
sudo ETCD_AUTHORITY=<ETCD HOST:PORT> ./calicoctl node --libnetwork
```

Again, be sure to set the ETCD_AUTHORITY to the correct `IP/Hostname:Port` for your etcd cluster.

3. Ensure calico's services are running by checking for two Calico containers in Docker:

```shell
$ docker ps
CONTAINER ID        NAMES               IMAGE                           CREATED
19263eda1810        calico-libnetwork   calico/node-libnetwork:v0.9.0   3 seconds
f237fb21d357        calico-node         calico/node:v0.22.0             3 seconds
```

4. Enable Docker Containerizer in Mesos.

By default, Mesos enables on the "Mesos" Containerizer. Be sure to also
enable the Docker Containerizer:

```shell
sh -c 'echo docker > /etc/mesos-slave/containerizers'
systemctl restart mesos-slave.service
```

## Next Steps

With Calico Installed, you're now ready to launch Calico-networked tasks. See the [Docker Containerizer Usage Guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/tutorials/docker) for information.
