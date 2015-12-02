# Mesos with Calico Networking
**Calico provides IP-Per-Container networking for your Mesos cluster.** The following collection of guides will walk you through the steps necessary to get up and running.

Note: IP-Per-Container Networking with Calico is an opt-in feature for Mesos Frameworks that launch tasks with [Networkinfo](https://github.com/apache/mesos/blob/0.26.0-rc3/include/mesos/mesos.proto#L1383). This means that your favorite Mesos Frameworks will not work with Calico until they have opted to include Networkinfo when launching tasks. Marathon is the first Framework planned to use this new feature, but its Mesos-networking support is not yet complete. 

Calico support is under development. Use the following information to ensure you choose the right version:
- Calico fully supports and recommends Mesos 0.26
- Calico supports Mesos 0.25, but we recommend against using it as there aren't any Frameworks (including Marathon) which support the Networkinfo specs from 0.25 (which were modified for 0.26)
- Calico works on Mesos 0.24, but only as a proof of concept, and is no longer supported.

Have any questions on these guides? Is there any material you want to see covered? Let us know on our [Slack channel](https://calicousers-slackin.herokuapp.com/).

## 1. Prepare Master and Agent Nodes
The [Mesos Host Preparation Guide](PrepareHosts.md) will walk you through hostname and firewall configuration for compatability between Calico and Mesos.

## 2. Prepare Core Services
Zookeeper and etcd serve as the backend datastores for Mesos and Calico, respectively. The [Core Services Preparation Guide](PrepareCoreServices.md) will walk you through setting up both services using Docker.

## 3. Calico
The following guides will help you install the Calico services required for each agent in your Mesos cluster.

### Calico With Docker (Recommended)
Calico is primarily distributed as a Docker container. Follow one of the guides below to set that up.

a.) [Install the Calico Networking in Mesos from RPM](RpmInstallCalico.md)

b.) [Manually Install Calico Networking in Mesos](ManualInstallCalico.md)

### Calico Without Docker
Don't want to use Docker in your Mesos Cluster? Calico can run directly on your Agent. Choose one of the following guides to install Calico without Docker.

c.) Create and Install the Dockerless Calico-Mesos RPM (coming soon)

d.) Manually Install Dockerless Calico (coming soon)

[calico]: http://projectcalico.org
[mesos]: https://mesos.apache.org/
[net-modules]: https://github.com/mesosphere/net-modules
[docker]: https://www.docker.com/

## 4. Mesos + Netmodules
Calico works in conjunction with [netmodules][net-modules], a Mesos Networking Module. Choose one of the following guides to install Mesos + Netmodules: 

a.)  We've bundled Mesos with netmodules into a convenient RPM - follow the [Mesos + Netmodules RPM Installation Guide](RpmInstallMesos.md) to install it.

b.) Already have mesos installed? Netmodules can be compiled onto an existing mesos deployment so long as all the mesos source files are present (therefore, unfortunately at this time, netmodules can not be added to mesos when installed via the mesosphere rpm releases). Follow the [manual netmodules compilation guide](ManualInstallNetmodules.md) to install it.

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/mesos/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
