---
title: About non-cluster hosts
description: Install Calico on hosts not in a cluster with network policy, or networking and network policy.
canonical_url: '/getting-started/bare-metal/about'
---

### Big picture

Secure non-cluster hosts by installing {{site.prodname}} for networking and/or networking policy.

### Value

Not all hosts in your environment run pods/workloads. You may have physical machines or legacy applications that you cannot move into a Kubernetes cluster, but still need to securely communicate with pods in your cluster. {{site.prodname}} lets you enforce policy on these **non-cluster hosts** using the same robust {{site.prodname}} network policy that you use for pods.

### Concepts

#### Non-cluster hosts and host endpoints

A **non-cluster host** is a computer that is running an application that is *not part of a Kubernetes cluster*. Using {{site.prodname}} network policy, you can secure these host interfaces using **host endpoints**. Host endpoints can have labels, and work the same as labels on pods/workload endpoints. 

The advantage is, you can write network policy rules to apply to both workload endpoints and host endpoints using label selectors; where each selector can refer to the either type (or be a mix of the two). For example, you can write a cluster-wide policy for non-cluster hosts that is immediately applied to every host. To learn how to restrict traffic to/from hosts using {{site.prodname}} network policy see, [Protect hosts]({{site.baseurl}}/security/protect-hosts). 

If you are using the etcd3 database, you can also install {{site.prodname}} with networking as described below.

#### Install options for non-cluster hosts

| Install {{site.prodname}} with... | Requires                         | Use case                                                     | Supported install methods                      |
| --------------------------------- | -------------------------------- | ------------------------------------------------------------ | ---------------------------------------------- |
| Policy only                       | An etcd3 or Kubernetes datastore | Use {{site.prodname}} network policy to control firewalls on non-cluster hosts. | Binary install with/ without a package manager |
| Networking and network policy     | An etcd3 datastore               | **Networking**<br />Use {{site.prodname}} networking (BGP, or overlay with VXLAN or IP-in-IP) to handle these communications:<br />- pod ↔ pod<br />- pod ↔ host<br /><br />**Note**: {{site.prodname}} does not handle host ↔ host networking; your underlying network must already be set up to handle this. <br /><br />**Policy**<br />Use {{site.prodname}} network policy to control firewalls on your non-cluster hosts. | Docker container                               |

### Before you begin

**Supported**

- All platforms in this release, except Windows  

**Required**

- Non-cluster host meets [system requirements](./requirements) for {{site.prodname}}. If you want to use a package manager for installation, the non-cluster host must be a system derived from Ubuntu or RedHat.
- Set up a datastore; if {{site.prodname}} is installed on a cluster, you already have a datastore
- Install `kubectl` or [`calicoctl`]({{site.baseurl}}/maintenance/clis/calicoctl/). (`kubectl` works only with the Kubernetes datastore.)

### Next steps

Select an install method.

>**Note**: {{site.prodname}} must be installed on each non-cluster host that you want to control with networking and/or policy. 
 {: .alert .alert-info}

| Install method                                               | Networking | Policy |
| ------------------------------------------------------------ | ---------- | ------ |
| [Docker container](./installation/container)                 | ✓          | ✓      |
| [Binary install with package manager](./installation/binary-mgr) |            | ✓      |
| [Binary install without package manager](./installation/binary) |            | ✓      |
