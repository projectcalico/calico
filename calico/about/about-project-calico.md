---
title: What is Project Calico?
description: Learn the value of Project Calico.
---

### What is Project Calico?

Project Calico is an open-source networking and network security solution for containers, virtual machines, and native host-based workloads. It runs in public clouds, on-premises, on a single node, or across a multi-thousand node cluster. {{site.prodname}} powers over 2M nodes daily across 166 countries.

### Why use Calico?

{{site.prodname}} was designed using best practice cloud-native design patterns, along with proven standards-based network protocols trusted worldwide by the largest internet carriers. Main features include:

- **Dataplane choices**

   eBPF, standard Linux, and Windows

- **Granular workload access controls**

   {{site.prodname}}'s network policy model for secure communication. Built-in support for Wireguard encryption to secure pod-to-pod traffic across the network.
  
- **Interoperability**

   {{site.prodname}} enables Kubernetes workloads and non-Kubernetes or legacy workloads to communicate seamlessly and securely. 

- **Thriving community**

    Leverage the innovation of 200+ contributors from a broad range of companies.


### Features

| Feature    | Description                                                  |
| ---------- | ------------------------------------------------------------ |
| Dataplanes | eBPF, standard Linux, and Windows.                           |
| Install    | Install Calico using operator or manifest install. <br />Extensive platform support.<br />Support for workloads and non-cluster hosts. |
| Upgrade    | Seamless upgrade from Calico to Calico Cloud and Calico Enterprise. |
| Networking | High-performance scalable pod networking using BPG or overlay networking. |
|            | Advanced IP address management.                              |
|            | Direct infrastructure peering without the overlay.           |
|            | Customize IPAM.                                              |
|            | Configure IP autodetection.                                  |
|            | Configure dual stack or IPv6 only.                           |
| Security   | Security policy enforcement for workload and host endpoints. |
|            | Data-in-transit encryption using WireGuard.                  |
|            | Policy examples for services, hosts, extreme traffic.        |
| Operations | Monitor and visualize Calico component metrics using Prometheus and Grafana. |
|            | Manage TLS certificates.                                     |
| CRDs       | Customize resources using Calico Customize Resource Definitions and APIs. |
| CLIs       | Supports kubectl and calicoctl command line tools.           |
