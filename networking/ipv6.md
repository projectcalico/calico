---
title: Configure dual stack or IPv6 only
description: Configure dual stack or IPv6 only for workloads.
canonical_url: '/networking/ipv6'
---

### Big picture

Configure {{site.prodname}} IP address allocation to use dual stack or IPv6 only for workload communications.

### Value

Workload communication over IPv6 is increasingly desirable, as well as or instead of IPv4. {{site.prodname}} supports:

- **IPv4 only** (default)

  Each workload gets an IPv4 address, and can communicate over IPv4.

- **Dual stack**

  Each workload gets an IPv4 and an IPv6 address, and can communicate over IPv4 and IPv6.

- **IPv6 only**

  Each workload gets an IPv6 address, and can communicate over IPv6.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **CNI plugin configuration** with `assign_ipv6` and `assign_ipv4` flags
- **IPPool**

### Before you begin...

**{{site.prodname}} requirements**

- {{site.prodname}} IPAM

**Kubernetes version requirements**
  - For dual stack, 1.16 and later
  - For one IP stack at a time (IPv4 or IPv6), any Kubernetes version

**Kubernetes IPv6 host requirements**
  - An IPv6 address that is reachable from the other hosts
  - The sysctl setting, `net.ipv6.conf.all.forwarding`, is set to `1`.
    This ensures both Kubernetes service traffic and {{site.prodname}} traffic is forwarded appropriately.
  - A default IPv6 route

**Kubernetes IPv4 host requirements**
  - An IPv4 address that is reachable from the other hosts
  - The sysctl setting, `net.ipv4.conf.all.forwarding`, is set to `1`.
    This ensures both Kubernetes service traffic and {{site.prodname}} traffic is forwarded appropriately.
  - A default IPv4 route

### How to

>**Note**: The following tasks are for new clusters.
{: .alert .alert-info}

**Manifest install**
- [Enable dual stack, manifest install](#enable-dual-stack-manifest-install)
- [Enable IPv6-only, manifest install](#enable-ipv6-only-manifest-install)

**Operator install**
- [Enable dual stack, operator install](#enable-dual-stack-operator-install)
- [Enable IPv6-only, operator install](#enable-ipv6-only-operator-install)

**Optional**
- [Change host IPv4 addresses to IPv6 only](#change-host-ipv4-addresses-to-ipv6-only)

#### Enable dual stack, manifest install

1. Set up a new cluster following the Kubernetes {% include open-new-window.html text='prerequisites' url='https://kubernetes.io/docs/concepts/services-networking/dual-stack/#prerequisites' %} and {% include open-new-window.html text='enablement steps' url='https://kubernetes.io/docs/concepts/services-networking/dual-stack/#enable-ipv4-ipv6-dual-stack' %}.

1. Using the [{{site.prodname}} Kubernetes install guide]({{site.baseurl}}/getting-started/kubernetes/self-managed-onprem/onpremises), download the right {{site.prodname}} manifest for the cluster and datastore type.

1. Edit the CNI config (`calico-config` ConfigMap in the manifest), and enable IPv4 and IPv6 address allocation by setting both fields to true.

   ```
       "ipam": {
           "type": "calico-ipam",
           "assign_ipv4": "true",
           "assign_ipv6": "true"
       },
   ```

1. Configure IPv6 support and the default IPv6 IP pool by adding the following variable settings to the environment for the `calico-node` container:

   | Variable name | Value |
   | ------------- | ----- |
   | `IP6`         | `autodetect` |
   | `FELIX_IPV6SUPPORT` | `true` |

1. For clusters **not** provisioned with kubeadm (see note below), also add the following environment variable to the environment for the `calico-node` container:

   | Variable name | Value |
   | ------------- | ----- |
   | `CALICO_IPV6POOL_CIDR` | the same as the IPv6 range you configured as the cluster CIDR to kube-controller-manager and kube-proxy |

   >**Note**: For clusters provisioned with kubeadm, {{site.prodname}} autodetects the IPv4 and IPv6 pod CIDRs and does not require configuration.
   {: .alert .alert-info}

1. Apply the edited manifest with `kubectl apply -f`.
   New pods will get IPv6 addresses as well as IPv4, and can communicate with each other and the outside world over IPv6.

#### Enable IPv6-only, manifest install

1. Set up a new cluster following the Kubernetes {% include open-new-window.html text='prerequisites' url='https://kubernetes.io/docs/concepts/services-networking/dual-stack/#prerequisites' %} and {% include open-new-window.html text='enablement steps' url='https://kubernetes.io/docs/concepts/services-networking/dual-stack/#enable-ipv4-ipv6-dual-stack' %}.

1. Using the [{{site.prodname}} Kubernetes install guide]({{site.baseurl}}/getting-started/kubernetes/self-managed-onprem/onpremises), download the appropriate {{site.prodname}} manifest for IPv6 deployment and save it as `calico.yaml`.

1. Edit the `calico.yaml` ipam section, and modify it to disable IPv4 assignments and enable IPv6 assignments.
   ```
       "ipam": {
           "type": "calico-ipam",
           "assign_ipv4": "false",
           "assign_ipv6": "true"
       },
   ```
1. Add the following environment variables to the calico-node DaemonSet in the `calico.yaml` file.
Be sure to set the value for `CALICO_IPV6POOL_CIDR` to the desired IP pool; it should match the `--cluster-cidr` passed to the kube-controller-manager and to kube-proxy.

   ```yaml
   - name: CALICO_IPV6POOL_CIDR
     value: "fd20::0/112"
   ```

1. In the `calico.yaml` file, verify that the environment variable `FELIX_IPV6SUPPORT` is set `true` on the calico-node DaemonSet.
1. Apply the `calico.yaml` manifest with `kubectl apply -f calico.yaml`.

   New pods will get IPv6 addresses, and can communicate with each other and the outside world over IPv6.

#### (Optional) Change host IPv4 addresses to IPv6 only

If you installed {{site.prodname}} on the cluster using the default IPv4, and you want switch the host to IPv6-only, follow these additional steps.

1. Disable [IP autodetection of IPv4]({{site.baseurl}}//networking/ip-autodetection) by setting `IP` to `none`.
1. Calculate the {{site.prodname}} BGP router ID for IPv6 using either of the following methods.
   - Set the environment variable `CALICO_ROUTER_ID=hash` on {{site.nodecontainer}}.
     This configures {{site.prodname}} to calculate the router ID based on the hostname, or
   - Pass a unique value for `CALICO_ROUTER_ID` to each node individually.

#### Enable dual stack, operator install

TBD - operator steps

#### Enable IPv6-only, operator install

TBD - operator steps

### Above and beyond

- [Configure the Kubernetes control plane to operate over IPv6]({{site.baseurl}}/networking/ipv6-control-plane)
