<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.13.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# RPM Install Calico + Mesos
This tutorial will walk you through installing Calico and a fresh Mesos installation with Netmodules using a pre-built RPM. At the completion of this guide, you will have a Mesos Slave ready to launch tasks with Calico networking.

Note: These RPMs do not serve as an official calico or mesos installation option, and will not receive a supported upgrade story for the future. They merely serve as a more automatic alternative to performing the steps in the [Manually Installing Calico + Mesos + Netmodules](ManualInstallCalicoMesos.md) guide. 

This RPM installation includes and installs:
- Mesos
- net-modules
- `calico_mesos` plugin binary
- `modules.json`, JSON file which points mesos to the location of `net-modules` and points `net-modules` to the `calico-mesos` plugin
- `calicoctl`, a command line tool for easily launching the calico-node service
- `calico.service`, a systemd service to ensure calico is always running

## 1. Download and Install the RPMs

    wget https://github.com/projectcalico/calico-mesos/releases/download/v0.1.3/calico-mesos-rpms.tar
    tar -xvf calico-mesos-rpms.tgz
    sudo yum install -y calico-mesos-rpms/*.rpm

> Note, Extra Packages for Enterprise Linux (EPEL) must be installed before installing Mesos + Net-Modules. You can download this package by calling `sudo yum install epel-release`

## 2. Start Calico Services
A systemd unit file has been provided to start the Calico processes needed by the calico_mesos plugin binary. When starting the calico-mesos service, the environment variable `ETCD_AUTHORITY` is used to point Calico to a running instance of etcd. This variable must be set in `/etc/default/mesos-slave`. Open this file and add the `ETCD_AUTHORITY` variable is set correctly, then run the following commands.

> Follow our [Mesos Cluster Preparation guide](MesosClusterPreparation.md#Install) if you do not already have an instance of etcd running to walk through installing etcd with Docker.

    sudo systemctl start calico-mesos.service
    sudo systemctl start mesos-slave.service

Check that Calico and Mesos are both running:

    sudo systemctl status calico-mesos.service
    sudo systemctl status mesos-slave.service

[calico-mesos]: https://github.com/projectcalico/calico-mesos/releases/latest

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/mesos/RpmInstallCalicoMesos.md?pixel)](https://github.com/igrigorik/ga-beacon)
