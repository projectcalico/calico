# Mesos with Calico Networking
**Calico provides IP-Per-Container networking for your Mesos cluster.** The following collection of guides will walk you through the steps necessary to get up and running.

Have any questions on these guides? Is there any material you want to see covered? Let us know on our [Slack channel](https://calicousers-slackin.herokuapp.com/).

## Prepare Master and Agent Nodes
The [Host Preparation Guide](PrepareHosts.md) will walk you through preparing each host in your cluster to be compatible with Calico and Mesos.

## Prepare Core Services
Zookeeper and etcd serve as the backend datastores for Mesos and Calico, respectively. The [Core Services Preparation Guide](PrepareCoreServices.md) will walk you through setting up both services using Docker.

## Mesos + Netmodules
Calico works in conjunction with [Net-Modules][net-modules], a Mesos Networking Module. The following guides will install Mesos with the necessary Net-Modules libraries. Choose the one that best suits your requirements. 
* [Install the Mesos + Net-Modules from an RPM](RpmInstallMesos.md)

## Calico
The following guides will help you install the Calico services required for each agent in your Mesos cluster.

### Calico With Docker (Recommended)
Calico is primarily distributed as a Docker container. Follow one of the guides below to set that up.
* [Install the Calico Networking in Mesos from RPM](RpmInstallCalico.md)
* [Manually Install Calico Networking in Mesos](ManualInstallCalico.md)

### Calico Without Docker
Don't want to use Docker in your Mesos Cluster? Calico can run directly on your Agent. Choose one of the following guides to install Calico without Docker.
* Create and Install the Dockerless Calico-Mesos RPM (coming soon)
* Manually Install Dockerless Calico (coming soon)

[calico]: http://projectcalico.org
[mesos]: https://mesos.apache.org/
[net-modules]: https://github.com/mesosphere/net-modules
[docker]: https://www.docker.com/