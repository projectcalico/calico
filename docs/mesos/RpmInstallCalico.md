# Add Calico Networking To Mesos with an RPM
This guide will walk you through adding Calico networking to your Mesos cluster using an RPM that can be built from the [calico-mesos repository](https://github.com/projectcalico/calico-mesos). You must follow these steps on *each Agent in your cluster*.

*This guide assumes you already have [Mesos + Net-Modules installed](https://github.com/projectcalico/calico-docker/tree/master/docs/mesos#mesos--netmodules) on your Agent(s).* 

# Download and Install the RPM
The Calico-Mesos RPM can be downloaded directly from the [calico-mesos repository releases](https://github.com/projectcalico/calico-mesos/releases/latest).

Alternatively, the RPM can easily be built via the [calico-mesos repository](https://github.com/projectcalico/calico-mesos).

    $ git clone https://github.com/projectcalico/calico-mesos.git
    $ cd calico-mesos
    $ make rpm
    $ sudo yum install dist/calico-mesos.rpm

# Start Calico Services
A systemd unit file has been provided to start the Calico processes needed by the calico_mesos plugin binary. When starting the calico-mesos service, the environment variable `ETCD_AUTHORITY` is used to point Calico to a running instance of etcd. This variable is set in `/etc/default/mesos-slave`. Open this file and ensure that the `ETCD_AUTHORITY` variable is set correctly, then run the following commands.

> Follow our [Core Services Preparation Guide](PrepareCoreServices.md) if you do not already have an instance of etcd running.

    $ sudo systemctl enable calico-mesos.service
    $ sudo systemctl start calico-mesos.service

You can check that Calico is successfully running by typing:

    $ sudo systemctl status calico-mesos.service

Or check Docker and look for the calico-node container.

    $ sudo docker ps | grep "calico-node"
