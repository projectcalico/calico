<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.20.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Calico with Docker Containerizer - Manual Install Guide

This document provides the commands to download and run Calico
for use with the Docker Containerizer in Mesos.

## Prerequisites

### Docker

To use the multi-host native networking feature of Docker, the Docker daemon
needs to be run with the cluster store parameter.  If using etcd as a cluster
store, run the Docker daemon with the following additional parameter:

    --cluster-store=etcd://<ETCD HOST>:<PORT>

Replacing `<ETCD HOST>:<PORT>` with the appropriate `IP/Hostname:Port`
for your etcd cluster.

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
sudo ETCD_AUTHORITY=<ETCD HOST:PORT> ./calicoctl node --libnetwork
```

Again, be sure to set the ETCD_AUTHORITY to the correct `IP/Hostname:Port` for your etcd cluster.

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

