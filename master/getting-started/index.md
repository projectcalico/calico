---
title: Calico Integrations
---

In general, all calico (container) installations require the same three components:

1. A central etcd cluster.

2. `calico/node`, a container packaged with Calico's core software, running on each Agent.

3. The relevant orchestrator networking plugin.

The means by which this are installed and setup varies greatly between orchestrators
and cloud environments.

The following pages will help you understand how to run and use Calico in these different environments.
In most cases we provide worked examples covering:

- Quickstart demo Clusters
- Manual setup instructions
- Streamlined orchestrator installation instructions
- Simple cloud set up demonstrations

Choose the relevant orchestrator for more information.

- [Calico with Kubernetes](kubernetes)
- [Calico with Docker](docker)
- [Calico with rkt](rkt)
- [Calico with Mesos](mesos)
- [Calico with DC/OS](mesos/installation/dc-os)
- [Calico with OpenStack](openstack)
