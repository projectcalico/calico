---
title: Calico with the Unified Containerizer - Manual Install Guide
---

> This guide explains how to add Calico networking to a Mesos Agent.
Specifically, we will add the Calico plugin to perform networking
for the Unified Containerizer.
- If you're looking for information on installing Calico with the Docker Containerizer, see [Docker Containerizer Manual Install Guide](ManualInstallCalicoDockerContainerizer)
- If you're not sure the difference between the Unified and Docker Containerizers, see  [Mesos' information on Containerizers](http://mesos.apache.org/documentation/latest/containerizer/) and [Our Readme on Calico's integration for each](index).


## Prerequisites
### Mesos-Agent with Mesos and Netmodules installed
This guide will focus on only the Calico components of a
calico-mesos-agent. You must have an agent with net-modules
activated.

### Docker
Calico's core services are run in a Docker container, so we'll need
Docker installed on every Agent in the cluster.
[Follow Docker's Centos installation guide](https://docs.docker.com/engine/installation/centos/)
for information on how to get Docker installed.

### Etcd
To run Calico, you'll need a running etcd store.
See the [Cluser Preparation guide](MesosClusterPreparation#etcd)
for information on how to quickly get one running.

## Install Calico-Mesos Components
The following calls will download the necessary Calico components.
Ensure you've created the `/calico` directory first (`mkdir -p /calico`).

  1. Download the `calico_mesos` plugin binary

  ```shell
  curl -L -o /calico/calico_mesos https://github.com/projectcalico/calico-mesos/releases/download/v0.1.5/calico_mesos
  chmod +x /calico/calico_mesos
  ```

  2. Download and enamble `modules.json` file

  ```shell
  curl -L -o /calico/modules.json https://raw.githubusercontent.com/projectcalico/calico-containers/master/docs/mesos/vagrant-centos/sources/modules.json 
  # activate modules in mesos-slave
  echo file:///calico/modules.json > /etc/mesos-slave/modules
  ```

  3. Set ETCD_AUTHORITY for the mesos-slave process, by replacing 
  `[etcd-ip:port]` with the location of your Etcd server

  ```shell
  echo ETCD_AUTHORITY=[etcd-ip:port] >> /etc/default/mesos-slave
  ```

  4. Run Calico Node
  The last Calico component required for Calico networking
  in Mesos is `calico-node`, a Docker image containing
  Calico's core routing processes.
 
  The `calico-node` container can easily be launched via
  `calicoctl`, Calico's command line tool. When doing so,
  we must provide the location of the running etcd instance
  by setting the `ECTD_AUTHORITY` environment variable.

  ```shell
  curl -L -o ./calicoctl https://github.com/projectcalico/calico-containers/releases/download/v0.18.0/calicoctl
  chmod +x calicoctl
  sudo ETCD_AUTHORITY=[etcd-ip:port] ./calicoctl node
  ```

  5. With the components in place, and mesos configured,
  we must restart the mesos-slave process using the appropriate
  service manager. For systemd, this will look like the
  following command:

  ```shell
  systemctl daemon-reload
  systemctl restart mesos-slave
  systemctl status mesos-slave
  ```

## Next steps
To test your cluster, follow our guide on [Using Calico-Mesos Unified Containerizer]
(UsageGuideUnifiedContainerizer) and start launching
tasks networked with Calico.

