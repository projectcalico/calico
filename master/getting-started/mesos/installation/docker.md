---
title: Installing Calico for the Docker Containerizer
---

This document provides the commands to download and run Calico
for use with the Docker Containerizer in Mesos.

## Prerequisites

#### 1. etcd

Calico uses etcd as its datastore. Ensure you have an instance of etcd running,
and that it is accessible from all Agents in your cluster.

To maximize availability, we recommend running an etcd cluster across your Mesos masters.
See [etcd's clustering guide](https://coreos.com/os/docs/latest/cluster-architectures.html)
for more information.

For testing, you can run a single instance of etcd using docker on your master
with the following command, ensuring you've correctly set `$ETCD_IP`:
```
docker run --detach \
	--net=host \
	--name etcd quay.io/coreos/etcd:v2.0.11 \
	--advertise-client-urls "http://$ETCD_IP:2379" \
	--listen-client-urls "http://$ETCD_IP:2379,http://127.0.0.1:2379"
```

#### 2. Docker Configured with Cluster Store

Under the covers, Calico networks Docker tasks for Mesos with its Docker CNM plugin.
Multihost Networking in Docker requires that
each Agent's Docker daemon must be configured with a cluster store.

Though Docker's configured cluster-store does not have to be the same as Calico's,
for simplicity, users can configure Docker to use the same by setting the
following flag when starting the docker daemon:

```shell
--cluster-store=etcd://<ETCD_IP>:<ETCD_PORT>
```

Replace `<ETCD_IP>` and `<ETCD_PORT>` with the appropriate `hostname:port` for your etcd cluster.

#### 3. Docker Containerizer Enabled for Mesos Agents

By default, Mesos only enables the "Mesos" Containerizer. Ensure
the Docker Containerizer is also enabled on each Agent.

If you are using the default `mesos-init-wrapper` from the official Mesos package,
you can enable the Docker Containerizer with the following command:

```shell
$ sh -c 'echo docker > /etc/mesos-slave/containerizers'
$ systemctl restart mesos-slave.service
```


## Installing Calico

Calico can be installed on each Mesos agent using the `calicoctl` command-line tool.

>Note: For production deployments, we recommend ensuring this task is always running
by backing it with an init system. Visit our guide on
[running Calico as a service]({{site.baseurl}}/{{page.version}}/usage/configuration/as-service)
to learn how to do this.

To start Calico on each agent, first download `calicoctl`:

```shell
$ curl -o /usr/bin/calicoctl -L http://www.projectcalico.org/builds/calicoctl
$ chmod a+x calicoctl
```

Then, use `calicoctl` to launch the `calico/node` container:

```shell
$ sudo ETCD_ENDPOINTS=http://<ETCD_IP>:<ETCD_PORT> ./calicoctl node run
```

Ensure calico's services are running and healthy using `calicoctl`'s status command:

```shell
$ sudo calicoctl node status
Calico process is running.

IPv4 BGP status
No IPv4 peers found.

IPv6 BGP status
No IPv6 peers found.
```

## Next Steps

With Calico Installed, you're now ready to launch Calico-networked tasks. See the [Docker Containerizer Usage Guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/tutorials/docker) for information.
