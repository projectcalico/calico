---
title: Configure Kubernetes control plane to operate over IPv6
description: Configure the Kubernetes control plane to operate over IPv6 for dual stack or IPv6 only.
canonical_url: '/networking/ipv6-control-plane'
---

### Big picture

If you have IPv6 connectivity between your nodes and workloads, you may also want to configure the Kubernetes control plane to operate over IPv6, instead of IPv4.

### How to
 
To configure Kubernetes components for IPv6 only, set the following flags. 

| Component                   | **Flag**                                      | **Value/Content**                                            |
| --------------------------- | --------------------------------------------- | ------------------------------------------------------------ |
| **kube-apiserver**          | `--bind-address` or `--insecure-bind-address` | Set to the appropriate IPv6 address or `::` for all IPv6 addresses on the host. |
|                             | `--advertise-address`                         | Set to the IPv6 address that nodes should use to access the `kube-apiserver`. |
| **kube-controller-manager** | `--master`                                    | Set with the IPv6 address where the `kube-apiserver` can be accessed. |
| **kube-scheduler**          | `--master`                                    | Set with the IPv6 address where the `kube-apiserver` can be accessed. |
| **kubelet**                 | `--address`                                   | Set to the appropriate IPv6 address or `::` for all IPv6 addresses. |
|                             | `--cluster-dns`                               | Set to the IPv6 address that will be used for the service DNS; this must be in the range used for `--service-cluster-ip-range`. |
|                             | `--node-ip`                                   | Set to the IPv6 address of the node.                         |
| **kube-proxy**              | `--bind-address`                              | Set to the appropriate IPv6 address or `::` for all IPv6 addresses on the host. |
|                             | `--master`                                    | Set with the IPv6 address where the `kube-apiserver` can be accessed. |

For dual stack settings, see {% include open-new-window.html text='Enable IPv4/IPv6 dual-stack' url='https://kubernetes.io/docs/concepts/services-networking/dual-stack/#prerequisites' %}.
