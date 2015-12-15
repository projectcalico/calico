<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.13.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Add Calico Networking To Mesos with an RPM
This tutorial will walk you through adding Calico networking to your Mesos cluster using an RPM that can be built from the [calico-mesos repository](https://github.com/projectcalico/calico-mesos). You must follow these steps on *each Agent in your cluster.*

This RPM includes and installs:
- `calico_mesos` plugin binary
- `modules.json`, JSON file which points mesos to the location of `net-modules` and points `net-modules` to the `calico-mesos` plugin.
- `calicoctl`, a command line tool for easily launching the calico-node service.
- `calico.service`, a systemd service to ensure calico is always running.

Alternative to using this RPM, you can manually download and install these components by following the [Manual Calico Mesos Installation tutorial](ManualInstallCalico.md)

## 1. Download and Install the RPM
The Calico-Mesos RPM can be downloaded directly from the [calico-mesos repository releases][calico-mesos].

Alternatively, the RPM can easily be built via the [calico-mesos repository](https://github.com/projectcalico/calico-mesos).

    $ git clone https://github.com/projectcalico/calico-mesos.git
    $ cd calico-mesos
    $ make rpm
    $ sudo yum install dist/calico-mesos.rpm

## 2. Start Calico Services
A systemd unit file has been provided to start the Calico processes needed by the calico_mesos plugin binary. When starting the calico-mesos service, the environment variable `ETCD_AUTHORITY` is used to point Calico to a running instance of etcd. This variable is set in `/etc/default/mesos-slave`. Open this file and ensure that the `ETCD_AUTHORITY` variable is set correctly, then run the following commands.

> Follow our [Core Services Preparation tutorial](PrepareCoreServices.md) if you do not already have an instance of etcd running.

    $ sudo systemctl enable calico-mesos.service
    $ sudo systemctl start calico-mesos.service

You can check that Calico is successfully running by typing:

    $ sudo systemctl status calico-mesos.service

Or check Docker and look for the calico-node container.

    $ sudo docker ps | grep "calico-node"

[calico-mesos]: https://github.com/projectcalico/calico-mesos/releases/latest

## 4. Next Steps 
With Calico installed, you're ready to [Install Mesos + Netmodules](README.md#4-mesos--netmodules)

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/mesos/RpmInstallCalico.md?pixel)](https://github.com/igrigorik/ga-beacon)
