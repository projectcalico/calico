---
title: Use IPVS kube-proxy
description: Use IPVS kube-proxy for performance improvements. 
canonical_url: '/networking/use-ipvs'
---

### Big picture

Use IPVS kube-proxy mode for load balancing traffic across pods.

### Value

No matter where you are on your journey with container networking, iptables will serve you well. However, if you are scaling above 1,000 services, it’s worth looking at potential performance improvements using kube-proxy IPVS mode.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **FelixConfiguration** with KubeNodePortRanges

### Concepts

#### Kubernetes kube-proxy

Kube-proxy process handles everything related to Services on each node. It ensures that connections to the service cluster IP and port go to a pod that backs the service. If backed by more than one pod, kube-proxy load-balances traffic across pods.

Kube-proxy runs in three modes: **userspace**, **iptables**, and **ipvs**. (Userspace is old, slow and not recommended.) Here’s a quick summary of iptables and ipvs modes.

| **kube-proxy mode** | **Designed to be...**                                        | **Linux kernel hooks**                 | **Connection processing overhead...**       |
| ------------------- | ------------------------------------------------------------ | -------------------------------------- | ------------------------------------------- |
| iptables            | An efficient firewall                                        | NAT pre-routing using sequential rules | Grows proportional to cluster size          |
| ipvs                | A load balancer with scheduling options like round-robin, shortest-expected delay, least connections, etc. | Optimized lookup routine               | Stays constant, independent of cluster size |

If you are wondering about the performance differences between iptables and ipvs, the answers are definitely not straightforward. For a comparison between iptables (including {{site.prodname}}’s own use of iptables) and ipvs modes, see {% include open-new-window.html text='Comparing kube-proxy modes: iptables or IPVS?' url='https://www.projectcalico.org/comparing-kube-proxy-modes-iptables-or-ipvs/' %}.

#### IPVS mode and NodePort ranges

Kube-proxy IPVS mode supports NodePort services and cluster IPs. {{site.prodname}} also uses NodePorts for routing traffic to the cluster, including the same default Kubernetes NodePort range (30000:32767).  If you change your default NodePort range in Kubernetes, you must also change it on {{site.prodname}} to maintain ipvs coverage.

#### iptables: when to change mark bits

To police traffic in IPVS mode, {{site.prodname}} uses additional iptables mark bits to store an ID for each local {{site.prodname}} endpoint. If you are planning to run more than 1,022 pods per host with IPVS enabled, you may need to adjust the mark bit size using the `IptablesMarkMask` parameter in {{site.prodname}} [FelixConfiguration]({{ site.baseurl }}/reference/felix/configuration#ipvs-bits).

#### {{site.prodname}} auto detects ipvs mode

When {{site.prodname}} detects that kube-proxy is running in IPVS mode (during or after installation), IPVS support is automatically activated.  Detection happens when calico-node starts up, so if you change kube-proxy's mode in a running cluster, you will need to restart your calico-node instances.

### Before you begin...

**Required**

- kube-proxy is configured to use IPVS mode
- Services for ipvs mode are type, NodePort

### How to

As previously discussed, there is nothing you need to do in {{site.prodname}} to use IPVS mode; if enabled, the mode is automatically detected. However, if your default Kubernetes NodePort range changes, use the following instructions to update {{site.prodname}} nodeport ranges to stay in sync.  Detection happens when calico-node starts up, so if you change kube-proxy's mode in a running cluster, you will need to restart your calico-node instances.

#### Change {{site.prodname}} default nodeport range

In the FelixConfiguration resource, change the configuration parameter for the default node port range (`KubeNodePortRange`,) in {{site.prodname}} to match your new default range in Kubernetes. For help, see [FelixConfiguration]({{ site.baseurl }}/reference/felix/configuration).
