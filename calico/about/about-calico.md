---
title: Calico Open Source
description: Networking and security for containers and Kubernetes
canonical_url: '/about/about-calico'
custom_css: css/intro.css
---

## Overview

Calico Open Source is a networking and security solution for containers, virtual machines, and native host-based workloads.
Calico supports a broad range of platforms including Kubernetes, OpenShift, Docker EE, OpenStack, and bare metal services.

Whether you opt to use Calico's eBPF data plane, Linux’s standard networking pipeline, or the Windows data plane, Calico delivers blazing-fast performance with true cloud-native scalability.
Calico provides developers and cluster operators with a consistent experience and set of capabilities whether running in public cloud or on-premises, or on a single node or across a multi-thousand node cluster.

## Benefits
<img src="https://www.tigera.io/app/uploads/2021/09/icon-52x52-Plugglable-dataplanes-eBPF-Windows-Linux.svg") Pluggable data planes including eBPF, Windows, VPP, and Linux

![icon](https://www.tigera.io/app/uploads/2021/09/icon-52x52-Any-kubernetes-distro-any-cloud.svg) "Any distro any cloud icon" %}Any container, any Kubernetes distro, any cloud

![icon](https://www.tigera.io/app/uploads/2021/09/icon-52x52-Unparallel-scalability-efficient-resource-utilization.svg) "Icon: scalability and resource utilization %} Unparalleled scalability & efficient resource utilization

![icon](https://www.tigera.io/app/uploads/2021/09/icon-52x52-Real-world-production-hardened.svg) Real-world production hardened
## Architecture
<!---
![A diagram of a Kubernetes cluster that shows where the Calico container network interface fits within the architechture %}
--->
## Capabilities

### Choice of data planes

![Multiple data planes({{ site.baseurl }}/images/intro/multiple-dataplanes.png)

Calico Open Source offers a choice of data planes, including a pure Linux eBPF data plane, a standard Linux networking data plane, and a Windows HNS data plane.
Calico combines cutting-edge features with standard primitives system administrators are already familiar with, to provide networking and security for containers and Kubernetes.

- [Linux eBPF]({{ site.baseURL }}/maintenance/enabling-bpf)
- [Linux iptables]({{ site.baseURL }}/archive/v3.19/reference/architecture/data-path)
- [Windows HNS]({{ site.baseURL }}/getting-started/windows-calico/)

### Full Kubernetes network policy support

![Best practices]({{ site.baseurl }}/images/intro/best-practices.png)

Calico Open Source’s network policy engine is the original reference implementation of Kubernetes network policy.
It implements the full set of features defined by the Kubernetes networking API, giving users all of the capabilities and flexibility envisaged when the API was originally defined.

- [Kubernetes network policy]({{ site.baseURL }}/about/about-network-policy)

### Kubernetes-native security policy model
![Security policy]({{ site.baseurl }}/images/intro/security-policy.png)
Calico Open Source translates networking and security best practices into a rich networking and security policy model for Kubernetes-native environments.
Calico makes it easy to allow or deny access to traffic according to DevOps, SRE, platform architect, security, and compliance teams.
The solution comes with built-in support for WireGuard encryption, with higher performance and lower CPU consumption.

Calico’s policy engine enforces the same policy model at the host networking layer and at the application layer.
Thus, it protects infrastructure from compromised workloads, and vice-versa.

- [Policy for hosts, VMs and Kubernetes]({{ site.baseURL }}/security/hosts)
- [Security policy for Kubernetes services]({{ site.baseURL }}/security/services)
- [Security policy for high-connection workloads]({{ site.baseURL }}/security/extreme-traffic)
### Best-in-class performance
{{ site.baseurl }}/images/intro/performance.png
Calico Open Source uses the Linux kernel’s built-in, highly optimized forwarding and access control capabilities to deliver native Linux networking data plane performance, typically without requiring any of the encap/decap overheads.
Calico’s control plane and policy engine are optimized to minimize overall CPU usage and occupancy, leading to higher performance and lower monthly bills.

- [High-performance scalable pod networking]({{ site.baseURL }}/networking/determine-best-networking#about-calico-networking)
### Workload interoperability

![Workload interoperability]({{ site.baseurl }}/images/intro/interoperability.png)

Calico Open Source enables Kubernetes workloads and non-Kubernetes or legacy workloads to communicate seamlessly and securely.
Calico can easily extend to secure existing host-based workloads (whether in the public cloud, or on-premises on VMs or bare metal servers) alongside Kubernetes.
All workloads are subject to the same network and security policy model for consistent enforcement of traffic flow externally and internally.

- [Direct infrastructure peering without the overlay]({{ site.baseURL }}/networking/vxlan-ipip)
- [Multi- and hybrid cloud]({{ site.baseURL }}/getting-started/kubernetes/self-managed-public-cloud/)
- [On-premises]({{ site.baseURL }}/getting-started/kubernetes/self-managed-onprem/)

### Scalable networking

![Scalable networking]({{ site.baseurl }}/images/intro/deployed.png)

Calico’s core design principles leverage best practice cloud-native design patterns combined with proven standards based network protocols trusted worldwide by the largest internet carriers.
The result is a solution with exceptional scalability that has been running at scale in production for years.
Calico’s development test cycle includes regularly testing multi-thousand node clusters.
Whether you are running a 10 node cluster, 100 node cluster, or more, you reap the benefits of the improved performance and scalability characteristics demanded by the largest Kubernetes clusters.

- [Kubernetes networking]({{ site.baseURL }}/networking/determine-best-networking#about-calico-networking)
- [Advanced IP address management]({{ site.baseURL }}/networking/ipam)

### Encryption

![Wireguard encryption]({{ site.baseurl }}/images/intro/wireguard-encryption.png)

Calico enables WireGuard to secure on-the-wire, in-cluster pod traffic in a Kubernetes cluster.
Calico automatically creates and manages WireGuard tunnels between nodes providing transport-level security for on-the-wire, in-cluster pod traffic.
WireGuard provides formally verified secure and performant tunnels without any specialized hardware.

- [Data-in-transit encryption]({{ site.baseURL }}/security/encrypt-cluster-pod-traffic)

## Key features

## How it works
imgages/felix_icon.png

Quickstart guide

Learn about Kuberntetes-native networking and security with Calico on a single-host Kubernetes cluster within approximately 15 minutes.


### Quickstart guide

Learn about Kubernetes-native networking and security with Calico on a single-host Kubernetes cluster within approximately 15 mins.