---
title: Configure Kubernetes control plane to operate over IPv6
description: Configure the Kubernetes control plane to operate over IPv6 for dual stack or IPv6 only.
canonical_url: '/networking/ipv6-control-plane'
---

### Big picture

Depending on your networking set up, you may want to configure the Kubernetes control plane to operate over IPv6 for dual stack or IPv6 only.

### How to
 
To configure Kubernetes components for IPv6 only, set the following flags. 

| Component   | **Flag**        | **Value/Content**                                            |
| ----------- | --------------- | ------------------------------------------------------------ |
| **kubelet** | `--address`     | Set to the appropriate IPv6 address or `::` for all IPv6 addresses. |
|             | `--cluster-dns` | Set to the IPv6 address that will be used for the service DNS; this must be in the range used for `--service-cluster-ip-range`. |
|             | `--node-ip`     | Set to the IPv6 address of the node.                         |

For dual stack settings, see {% include open-new-window.html text='Enable IPv4/IPv6 dual-stack' url='https://kubernetes.io/docs/concepts/services-networking/dual-stack/#prerequisites' %}.
