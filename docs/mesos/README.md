<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.19.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Mesos with Calico networking
Calico can be used as a network plugin for Mesos both for the Docker
Containerizer and the Unified Containerizer.

### Docker Containerizer
Calico with the Docker Containerizer uses a Calico network and IPAM
driver that hooks directly into the Docker networking infrastructure.
Docker networks using the Calico plugin are created up-front, and Mesos
can then be used to launch Docker containers using these networks.  Each
network is associated with a single Calico profile.  Fine grained policy
can be modified using the `calicoctl profile` commands.

### Unified Containerizer
Calico with the Unified Containerizer uses the [Calico Mesos plugin]
(https://github.com/projectcalico/calico-mesos) to configure
networking for a Mesos agent that is using the [net-modules network
isolator](https://github.com/mesosphere/net-modules). Networks are
specified as net-groups when launching a Mesos task.  A Calico
profile is automatically created for each net-group (if it doesn't
already exist), defaulting to allow communication between containers
using the same net-group.  Fine grained policy can be modified using
the `calicoctl profile` commands.

## Cluster Configuration Requirements
The installation requirements to use Calico networking are different
depending on whether you are using the Docker Containerizer or the
Unified Containerizer.  When setting up your cluster, follow the
appropriate guide based on your requirements.

Calico is particularly suitable for large Mesos deployments on bare
metal or private clouds, where the performance and complexity costs of
overlay networks can become significant. It can also be used in public
clouds.

If you have an existing Mesos cluster, follow the appropriate
installation guide. However, please ensure that Mesos (and Marathon
if you are using it) are installed at the appropriate minimum
version, upgrading if necessary.

## Guides

To build a new Mesos cluster with Calico networking, try one of the
following guides:

#### Quick Start a Sample Cluster:
- [Centos Vagrant guide](Vagrant.md) - set up a Calico Mesos cluster with
  one Mesos Master and two Mesos Agents.
  - This is the easiest way to set up a cluster with all of the required
  services running to launch tasks with either the Unified Containerizer or
  Docker Containerizer.

#### Installation guides:
- [DC/OS Calico Install Guide](./DCOS.md) -
  install Calico using Mesos' DC/OS web interface.
- [Manual Install Calico Unified Containerizer Guide](ManualInstallCalicoUnifiedContainerizer.md) -
  install Calico for use with the Unified Containerizer.
- [Manual Install Calico Docker Containerizer Guide](ManualInstallCalicoDockerContainerizer.md) -
  install Calico for use with the Docker Containerizer.
- [Mesos Cluster Preparation Guide](MesosClusterPreparation.md) - installation
  instructions for running required services of a Calico Mesos cluster.

#### Demonstration guides:
- [Docker Containerizer Usage Guide](UsageGuideDockerContainerizer.md) - configure
  and launch tasks with Calico using the Docker Containerizer.
- [Unified Containerizer Usage Guide](UsageGuideUnifiedContainerizer.md) - configure
  and launch tasks with Calico using the Unified Containerizer.
- [Stars demo](stars-demo/) - use the Docker Containerizer to show
  a network policy visualization of how a Calico cluster is configured.

## Contact Us

Get in touch with us directly in our `#mesos` channel on
[Slack](https://calicousers.slack.com)
([sign up here](https://calicousers-slackin.herokuapp.com/))!

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/mesos/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
