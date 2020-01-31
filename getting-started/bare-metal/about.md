---
title: About non-cluster hosts
description: Secure hosts not in a cluster by installing Calico with networking and/or networking policy enabled.
canonical_url: '/getting-started/bare-metal/about'
---

### Big picture

Secure hosts not in a cluster by installing {{site.prodname}} with networking and/or networking policy enabled.

### Value

Not all hosts in your environment run virtualized workloads (i.e. containers managed by Kubernetes or OpenShift, or VMs managed by OpenStack). There may be physical machines or legacy applications that you cannot move into an orchestrated cluster that need to communicate securely with workloads in your cluster. Whether you have a thousand machines or ten, {{site.prodname}} lets you enforce policy on them using the same robust {{site.prodname}} network policy that is used for workloads. 


### Concepts

#### Workloads and Hosts

We use the term workload to mean a pod or VM running as a guest on a computer with {{site.prodname}} installed. If your cluster is a Kubernetes or OpenShift cluster, workloads are pods, if your cluster is an OpenStack cluster, workloads are VMs. 

We use the term host to mean a computer where {{site.prodname}} is installed. These include computers that are part of a cluster and “host” workloads, as well as computers that are not part of the cluster and run applications directly, which we call "non-cluster" hosts.  {{site.prodname}} does not handle the networking from host to host ({{site.prodname}} assumes this is set up), but it can be used to handle networking between hosts and workloads.  {{site.prodname}} can also provide network policy for hosts, regardless of whether or not the hosts run any workloads.  This guide focuses on non-cluster hosts.

#### {{site.prodname}} networking on non-cluster hosts

When {{site.prodname}} networking is enabled, {{site.prodname}} provides the virtual networking for the workloads in your cluster, allowing them to communicate with one another. It is also responsible for setting up networking so that hosts can communicate with workloads and vice versa.  {{site.prodname}} does not handle networking for host to host communications.

When {{site.prodname}} networking is enabled...

| Communication type   | Handled by         |
|----------------------|--------------------|
| Workload ↔ Workload  | {{site.prodname}}  |
| Workload ↔ Host      | {{site.prodname}}  |
| Host ↔ Host          | Underlying network |

This means that if you are using {{site.prodname}} networking in your cluster, and you want the non-cluster hosts to be able to communicate with workloads in the cluster, you will need to install {{site.prodname}} for networking on your non-cluster hosts.  If you are not using {{site.prodname}} for networking in your cluster (e.g. are using {{site.prodname}} in policy-only mode), or don't need your non-cluster hosts to communicate directly with workloads, you can install {{site.prodname}} in policy-only mode on your non-cluster hosts.

#### {{site.prodname}} policy on non-cluster hosts

{{site.prodname}} policy allows you to control firewalls on your non-cluster hosts using the same controls powerful controls as in your cluster.  {{site.prodname}} must be running on each non-cluster host you want to control.

Using {{site.prodname}}, you can secure network interfaces of the host; these interfaces are called **host endpoints** (to distinguish them from **workload endpoints**). Host endpoints can have labels, which work the same as labels on workload endpoints. This allows you to create {{site.prodname}} network policy for either host or workload endpoints, where each selector can refer to the either type (or be a mix of the two) using labels.


### Before you begin...

1. Check that your hosts meet the [system requirements](./requirements) for {{site.prodname}}
1. Set up a datastore (if you have installed {{site.prodname}} on a cluster you will already have this)
1. [Install and configure calicoctl]({{site.baseurl}}/getting-started/calicoctl/)
1. Choose an install method and whether to use {{site.prodname}} for networking & policy, or policy-only

| Install method                                                       | Networking | Policy |
|----------------------------------------------------------------------|------------|--------|
| [Docker container](./installation/container)                         | ✓          | ✓      |
| [Binary install with package manager](./installation/binary-mgr)     |            | ✓      |
| [Binary install without package manager](./installation/binary)      |            | ✓      |
