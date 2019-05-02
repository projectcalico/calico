---
title: Calico Networking for Mesos
canonical_url: 'https://docs.projectcalico.org/v2.6/getting-started/mesos/index'
---

Calico introduces ip-per-container & fine-grained security policies to Mesos, while
maintaining speed and scalability and rendering port-forwarding obsolete.

Mesos supports several different Networking API's depending on which
Containerizer is being used. Calico provides compatible plugins for each.
Below, we list guides for each:

1. Quickstart scripts to launch a demo Mesos cluster pre-configured with Calico.
2. Manual instructions on adding Calico to a standard Mesos Cluster.
3. Usage guide detailing how to launch applications networked with Calico for
the described networking interface.

### a.) Docker Containerizer
Tasks launched in Mesos using the Docker Containerizer (i.e. Docker Engine) are
networked by Calico's Docker-libnetwork plugin. Once installed on each Mesos
Agent, operators can create Docker networks up-front, then launch Docker
tasks on them.

- [Quickstart with Vagrant Install: Calico for Docker Tasks in Mesos]({{site.baseurl}}/{{page.version}}/getting-started/mesos/vagrant/)
- [Manual Install: Calico for Docker Tasks in Mesos]({{site.baseurl}}/{{page.version}}/getting-started/mesos/installation/docker)
- [Usage Guide: Launching Docker Tasks networked by Calico in Mesos]({{site.baseurl}}/{{page.version}}/getting-started/mesos/tutorials/docker)

### b.) Unified Containerizer with CNI
Mesos v1.0.0 has introduced first-class support of the [Container Network
Interface (CNI)](https://github.com/containernetworking/cni) for the Unified
Containerizer.

- [Quickstart with Docker-Compose: Calico for Mesos CNI]({{site.baseurl}}/{{page.version}}/getting-started/mesos/demos/cni)
- [Manual Install: Calico for Mesos Tasks (CNI)]({{site.baseurl}}/{{page.version}}/getting-started/mesos/installation/unified)
- [Usage Guide: Launching Mesos Tasks networked with Calico CNI]({{site.baseurl}}/{{page.version}}/getting-started/mesos/tutorials/unified)

## Calico for DC/OS
Calico maintains a Framework for DC/OS which serves as an installer to quickly
add Calico to Mesos.
Calico's DC/OS package installs and configures everything you need to use Calico
with the Docker Containerizer and the Unified Containerizer (using CNI).
See the [Calico for DC/OS 1.8 Install Guide]({{site.baseurl}}/{{page.version}}/getting-started/mesos/installation/dc-os) for more information.
