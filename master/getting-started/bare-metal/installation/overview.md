---
title: Overview
---

### Big picture

Secure hosts by installing {{site.prodname}} networking and/or networking policy.

### Value

Not all hosts in your CaaS implementation (including bare metal) directly manage pods using Kubernetes, OpenStack, or OpenShift. There will always be physical machines or legacy databases that you cannot containerize or get rid of that need a firewall manager. Whether you have a thousand physical machines or ten, {{site.prodname}} lets you enforce policy on them using the same robust {{site.prodname}} network policy that is used for workloads. 

Host protection using {{site.prodname}} network policy is a key differentiators between {{site.prodname}} and other products. The host protection options are:

- **Networking and network policy**
  If your host needs to be aware of pods on other {{site.prodname}} hosts (even though it may not directly manage them), you must install **{{site.prodname}} networking** and **{{site.prodname}} network policy**.

- **Network policy only**
  If your host does not use {{site.prodname}} networking, are not managing pods, and does not need to be aware of pods on other {{site.prodname}} hosts, you can install just {{site.prodname}} network policy. 

### Features

This how-to guide uses the following {{site.prodname}} features:

- **Node**
- **FelixConfiguration**

### Concepts

#### {{site.prodname}} resources for host protection

If you are installing only {{site.prodname}} network policy, calico/node is the resource that identifies the host during installation, and FelixConfiguration is the resource used to enforce network policy. If you are installing both {{site.prodname}} networking with BPG and network policy on the host, you gain access to the full {{site.prodname}} product and resources.

#### Host endpoints and the magic of labeling

Using {{site.prodname}}, you can secure network interfaces of the host; these interfaces are called host endpoints (to distinguish them from workload endpoints). Host endpoints can have labels, and their labels are in the same “namespace” as workload endpoints. This allows you to create security rules for either endpoint type, each of which can to refer to the other (or a mix of the two), using labels and selectors.

### Before you begin...

#### Host requirements

- AMD64 processor
- Linux kernel 3.10 or later 
  The following distributions have the required kernel dependencies, and are known to work well with {{site.prodname}} and host protection.
  - RedHat Linux 7
  - CentOS 7
  - CoreOS Container Linux stable
  - Ubuntu 16.04
  - Debian 8
   **Note**: If you are using a different Linux version or distribution, the required kernel dependencies are:
   - `nf_conntrack_netlink subsystem`
   - `ip_tables (IPv4)`
   - `ip6_tables`
   - `ip_set`
   - `xt_set` 
   - `ipt_set`
   - `ipt_rpfilter`
   - `ipt_REJECT`
   - `ipip (if using Calico networking)`

#### Datastore requirements

{{site.prodname}} requires the etcdv3 datastore. 

#### Install and configure calicoctl

Before you start installation, the `calicoctl` command line tool must be installed and connected to your etcd datastore.

1. [Install calicoctl as a single host binary]({{site.baseurl}}/{{page.version}}/getting-started/calicoctl/install#installing-calicoctl-as-a-binary-on-a-single-host)

1. [Configure calicoctl to connect to etcd]({{site.baseurl}}/{{page.version}}/getting-started/calicoctl/configure/etcd)

### How to...

Based on your host requirements, use the following instructions to install {{site.prodname}} on a host.

>**Note**: If you are using OpenStack hosts, all of the options below are available. But you have another option -- you can install {{site.prodname}} network policy (with/without package manager) and install the Bird component separately for networking.

- [Install C{{site.prodname}}networking and network policy]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/installation/host-both)
  Hosts require Docker.

- [Install only {{site.prodname}} network policy with package manager]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/installation/host-only-policy)
  Use a package manager (PPA or RPM). For hosts running Red Hat Enterprise Linux (RHEL), Ubuntu, and CentOS.

- [Install only C{{site.prodname}} network policy, no package manager]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/installation/host-only-policy)
  Extract the binary and copy to each host.