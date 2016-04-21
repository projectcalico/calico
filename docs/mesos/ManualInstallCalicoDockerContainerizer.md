<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Calico with Docker Containerizer - Manual Install Guide

This document provides the commands to download and run Calico
for use with the Docker Containerizer in Mesos.

## Prerequisites

You will need to configure your Docker daemon on each agent to point at
the etcd cluster store, as seen in our [Manual Setup guide]
(../calico-with-docker/docker-network-plugin/ManualSetup.md#docker).

## Install and Run Calico
It is very easy to install Calico to use with the
Docker Containerizer.

On each of your agents, you will need to download the `calicoctl` command-line tool:

```
curl -o /usr/bin/calicoctl -L https://github.com/projectcalico/calico-containers/releases/download/v0.18.0/calicoctl
chmod a+x calicoctl 
```

Now, you will need run the `calico/node` and
`calico/node-libnetwork` containers.

For production deployments, we recommend running the two
containers as services. Visit our guide on [running Calico
as a Service](../CalicoAsService.md) to learn how to do this.

For test environments that you would like to get up and running
quickly, you can run the `calicoctl node --libnetwork`:

```
sudo ETCD_AUTHORITY=<HOST:PORT> ./calicoctl node --libnetwork
```

> Be sure to set the ETCD_AUTHORITY to the correct `IP/Hostname:Port` for your etcd cluster.

Once you've started the Calico services or you've run the `node` command,
you should see two Calico containers running in Docker:

```
$ docker ps
CONTAINER ID        NAMES               IMAGE                           CREATED
19263eda1810        calico-libnetwork   calico/node-libnetwork:v0.8.0   3 seconds
f237fb21d357        calico-node         calico/node:v0.18.0             3 seconds
```

## Configure Mesos for Docker Containerizer

You'll have to tell Mesos to use the Docker Containerizer.

Run the following commands on each agent to intialize the mesos-slave
process with the Docker Containerizer:

```
sh -c 'echo docker > /etc/mesos-slave/containerizers'
systemctl restart mesos-slave.service
```

That's it! You're ready to launch Calico-networked tasks. Visit
our [Docker Contaerinizer Usage Guide](./UsageGuideDockerContainerizer.md)
to get started.

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/mesos/ManualInstallCalicoDockerContainerizer.md?pixel)](https://github.com/igrigorik/ga-beacon)

