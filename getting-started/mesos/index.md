---
title: Calico Networking for Mesos
---

Calico introduces ip-per-container & fine-grained security policies to Mesos, while
maintaining speed and scalability and rendering port-forwarding obsolete.

Mesos supports several different Networking API's depending on which
Containerizer is being used. Calico provides compatible plugins for each.
Below, we list three different guides for each:

1. Quickstart scripts to launch a demo Mesos cluster pre-configured with Calico.
2. Manual instructions on adding Calico to a standard Mesos Cluster.
3. Usage guide detailing how to launch applications networked with Calico for
the described networking interface.

### a.) Docker Containerizer
Tasks launched in Mesos using the Docker Containerizer (i.e. Docker Engine) are
networked by Calico's Docker-Libnetwork plugin. Once installed on each Mesos
Agent, operators can create Docker networks up-front, then launch Docker
tasks on them.

- [Quickstart with Vagrant Install: Calico for Docker Tasks in Mesos](Vagrant)
- [Manual Install: Calico for Docker Tasks in Mesos](ManualInstallCalicoDockerContainerizer)
- [Usage Guide: Launching Docker Tasks networked by Calico in Mesos](UsageGuideDockerContainerizer)

### b.) Unified Containerizer with CNI
Mesos v1.0.0 has introduced first-class support of the [Container Network
Interface (CNI)](https://github.com/containernetworking/cni) for the Unified
Containerizer.

- [Quickstart with Docker-Compose: Calico for Mesos CNI](cni-compose-demo/)
- [Manual Install: Calico for Mesos Tasks (CNI)](ManualInstallCalicoCNI)
- [Usage Guide: Launching Mesos Tasks networked with Calico CNI](UsageGuideUnifiedCNI)

### c.) Unified Containerizer with Net-Modules [Deprecated]

**Note: The net-modules API is deprecated as it only currently supports Mesos 0.28.0.**

Calico's net-modules plugin
([calico-mesos](https://github.com/projectcalico/calico-mesos))
performs networking isolation for the Unified Containerizer by responding
to the
[networking hooks](https://github.com/mesosphere/net-modules/blob/master/api.md)
executed by the
[net-modules network isolator](https://github.com/mesosphere/net-modules).

Calico enforces
["net-groups"](https://github.com/apache/mesos/blob/master/include/mesos/mesos.proto#L1779)
as Calico profiles, which allows communication between containers
using the same net-group.  Fine grained policy for each net-group can be
modified using the `calicoctl profile` commands.

To get started, you'll need a Agent with net-modules compiled.

- [Quickstart with Docker-Compose: Calico for Mesos Tasks in Mesos using net-modules](https://github.com/mesosphere/net-modules)
- [Manual Install: Calico for Unified Containerizer (net-modules)](ManualInstallCalicoUnifiedContainerizer)
- [Usage Guide: Launching Mesos Tasks with Calico using net-modules with the Unified Containerizer](UsageGuideUnifiedContainerizer)

## Calico for DC/OS
Calico maintains a Framework for DC/OS which serves as an installer to quickly
add Calico to Mesos.
Calico's DC/OS package installs and configures everything you need to use Calico
with the Docker Containerizer and the Unified Containerizer (using CNI).
See the [Calico for DC/OS 1.8 Install Guide](./DCOS.md) for more information.
