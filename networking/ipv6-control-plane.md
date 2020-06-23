---
title: Configure the Kubernetes control plane to operate over IPv6
description: Configure the Kubernetes control plane to operate over IPv6 for dual stack or IPv6 only.
canonical_url: '/networking/ipv6'
---

### Big picture

Configure the Kubernetes control plane to operate over IPv6 for dual stack or IPv6 only.

### Value


### How to

#### Configure the Kubernetes control plane to operate over IPv6

Depending on your networking set up, you may want to configure the Kubernetes control plane to operate over IPv6 for dual stack or IPv6 only.
 
To configure Kubernetes components, enable IPv6 using the following flags.  

| Component                   | **Flag**                                      | **Value/Content**                                            |
| --------------------------- | --------------------------------------------- | ------------------------------------------------------------ |
| **kube-apiserver**          | `--bind-address` or `--insecure-bind-address` | Set to the appropriate IPv6 address or `::` for all IPv6 addresses on the host. |
|                             | `--advertise-address`                         | Set to the IPv6 address that nodes should use to access the `kube-apiserver`. |
|                             | `--service-cluster-ip-range`                  | Set to an IPv6 CIDR that will be used for the Service IPs. The DNS service address must be in this range. |
| **kube-controller-manager** | `--master`                                    | Set with the IPv6 address where the `kube-apiserver` can be accessed. |
|                             | `--cluster-cidr`                              | Set to match the {{site.prodname}} IPv6 IPPool.              |
| **kube-scheduler**          | `--master`                                    | Set with the IPv6 address where the `kube-apiserver` can be accessed. |
| **kubelet**                 | `--address`                                   | Set to the appropriate IPv6 address or `::` for all IPv6 addresses. |
|                             | `--cluster-dns`                               | Set to the IPv6 address that will be used for the service DNS; this must be in the range used for `--service-cluster-ip-range`. |
|                             | `--node-ip`                                   | Set to the IPv6 address of the node.                         |
| **kube-proxy**              | `--bind-address`                              | Set to the appropriate IPv6 address or `::` for all IPv6 addresses on the host. |
|                             | `--master`                                    | Set with the IPv6 address where the `kube-apiserver` can be accessed. |
|                             | `--cluster-cidr`                              | Set to match the {{site.prodname}} IPv6 IPPool.  
