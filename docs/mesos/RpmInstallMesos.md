# Create and Install the Mesos + Net-Modules RPM
This guide will walk you through building and installing Mesos + Net-Modules from RPMs. These RPMs will automate the installation of everything needed to run Mesos + Net-Modules in your cluster.

## Build and Install the RPM
The Mesos + Net-Modules RPMs can easily be built and installed via the [net-modules repository](https://github.com/mesosphere/net-modules).
> Note, Extra Packages for Enterprise Linux (EPEL) must be installed before installing Mesos + Net-Modules. You can download this package by calling `sudo yum install epel-release`

    $ git clone https://github.com/mesosphere/net-modules.git
    $ cd net-modules
    $ git checkout integration/0.25
    $ make builder-rpm
    $ sudo yum install packages/rpms/RPMS/x86_64/*.rpm

## Configure and Run Master

We will be need to set the correct environment variables for the master. These environment variables are interpreted the same way as command line arguments with the corresponding name in the mesos-master application at runtime.
> An explanation of the configuration options for Mesos can be found by running `mesos-init-wrapper -h`. 

First, you will need set the ZooKeeper URL in `/etc/mesos/zk`. Modify the line to include the IP address of the host where ZooKeeper is running.

> Follow our [Core Services Preparation Guide](PrepareCoreServices.md) if you do not already have an instance of ZooKeeper running.

The value in `/etc/mesos-master/quorum` may need to change depending on how many master hosts you have in your cluster. Mesos recommends that the quorum count is at least 1/2 the number of master hosts running. 

Now you may run the mesos-master process on your master host.

    $ sudo systemctl enable mesos-master.service
    $ sudo systemctl start mesos-master.service

## Configure and Run Agent(s)

We will be need to set the correct environment variables for each agent. These environment variables are interpreted the same way as command line arguments with the corresponding name in the mesos-slave application at runtime.
> An explanation of the configuration options for Mesos can be found by running `mesos-init-wrapper -h`. 

Append the following lines to `/etc/default/mesos-slave` on each of your agent hosts. 

> Note, Mesos does not install `/calico/modules.json`, which is specified with the environment variable `MESOS_MODULES`. Follow one of our [Calico installation guides](https://github.com/projectcalico/calico-docker/tree/master/docs/mesos#calico) to ensure that `modules.json` is placed correctly.

    MESOS_RESOURCES="ports(*):[31000-31100]"
    MESOS_MODULES=file:///calico/modules.json
    MESOS_ISOLATION=com_mesosphere_mesos_NetworkIsolator
    MESOS_HOOKS=com_mesosphere_mesos_NetworkHook
    MESOS_EXECUTOR_REGISTRATION_TIMEOUT=5mins
    ETCD_AUTHORITY=<IP of host with etcd running>:4001
    
Now you may run the mesos-slave process on each of your agent hosts.

    $ sudo systemctl enable mesos-slave.service
    $ sudo systemctl start mesos-slave.service


[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/mesos/RpmInstallMesos.md?pixel)](https://github.com/igrigorik/ga-beacon)
