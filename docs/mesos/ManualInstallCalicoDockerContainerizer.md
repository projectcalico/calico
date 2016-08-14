<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.21.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Calico with Docker Containerizer - Manual Install Guide

This document provides the commands to download and run Calico
for use with the Docker Containerizer in Mesos.

## Prerequisite: Docker
Calico networks Docker tasks for Mesos with its libnetwork plugin. In order to
run the libnetwork plugin, the Docker daemon on each agent must be configured
with a cluster store.

If using etcd as a cluster store, for example, run the Docker daemon with the
following additional parameter:

    --cluster-store=etcd://<ETCD HOST>:<PORT>

Replacing `<ETCD HOST>:<PORT>` with the appropriate `hostname:port`
for your etcd cluster.

## Install and Run Calico
It is very easy to install Calico to use with the
Docker Containerizer.

1. On each Mesos Agents, download the `calicoctl` command-line tool:

  ```
  curl -o /usr/bin/calicoctl -L http://www.projectcalico.org/builds/calicoctl
  chmod a+x calicoctl
  ```

2. Launch the `calico/node` and `calico/node-libnetwork` containers.

  For production deployments, we recommend running the two
  containers as services. Visit our guide on [running Calico
  as a Service](../CalicoAsService.md) to learn how to do this.

  For test environments that you would like to get up and running
  quickly, you can launch the container with `calicoctl`:

  ```
  sudo ETCD_AUTHORITY=<ETCD HOST:PORT> ./calicoctl node --libnetwork
  ```

  Again, be sure to set the ETCD_AUTHORITY to the correct `IP/Hostname:Port` for your etcd cluster.

3. Ensure calico's services are running by checking for two Calico containers in Docker:

  ```
  $ docker ps
  CONTAINER ID        NAMES               IMAGE                           CREATED
  19263eda1810        calico-libnetwork   calico/node-libnetwork:latest   3 seconds
  f237fb21d357        calico-node         calico/node:latest              3 seconds
  ```

4. Enable Docker Containerizer in Mesos.

  By default, Mesos enables on the "Mesos" Containerizer. Be sure to also
  enable the Docker Containerizer:

  ```
  sh -c 'echo docker > /etc/mesos-slave/containerizers'
  systemctl restart mesos-slave.service
  ```

That's it! You're ready to launch Calico-networked tasks. Visit
our [Docker Containerizer Usage Guide](./UsageGuideDockerContainerizer.md)
to get started.

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/mesos/ManualInstallCalicoDockerContainerizer.md?pixel)](https://github.com/igrigorik/ga-beacon)
