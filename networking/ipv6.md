---
title: Enable IPv6 only or dual stack
description: Enable IPv6 only or dual stack for workloads.
canonical_url: '/networking/ipv6'
---

### Big picture

Enable {{site.prodname}} IP address allocation to use IPv6 only or dual stack for workload communications.

### Value

Although communication over IPv6 is increasingly desirable as the natural mode for workloads, it is often a requirement to continue support for IPv4. {{site.prodname}} supports:

- IPv6 only
  Workloads can communicate over IPv6, initiate connections to IPv6 services, and terminate incoming IPv6 connections.
- **Dual stack**
   New pods get IPv6 addresses as well as IPv4 addresses, and can communicate with each other and the outside world over IPv6.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **IPAM**, a CNI plugin configuration with `assign_ipv6` and `assign_ipv4` flags
- **IPPool**

### Before you begin...

**{{site.prodname}} requirements**

  {{site.prodname}} IPAM
  The defaut mode is **IPv4**.

**Kubernetes version requirements**
  - For dual stack (alpha level), 1.16 and 1.17
  - 1.15 and earlier supports only one IP stack at a time (IPv6 or IPv4)

**Kubernetes IPv6 host requirements**
  - An IPv6 address that is reachable from the other hosts
  - The sysctl setting, `net.ipv6.conf.all.forwarding`, is set to `1`.
    This ensures both Kubernetes service traffic and {{site.prodname}} traffic is forwarded appropriately.
  - A default IPv6 route

### How to

>**Note**: The following tasks work only for new clusters; you cannot migrate existing IPv4 clusters to IPv6.
{: .alert .alert-info}

**Kubernetes install**
- [Enable dual stack, Kubernetes](#enable-dual-stack)
- [Enable IPv6-only, initial install, Kubernetes](#enable-ipv6-only-initial-manifest-install)
- [Enable IPv6-only, after install, Kubernetes](#enable-ipv6-only-after-install,kubernetes)

**OpenShift install**
- [Enable dual stack, OpenShift](#enable-dual-stack-openshift)
- [Enable IPv6-only, OpenShift](#enable-ipv6-only-openshift)

- (Optional)[Configure the Kubernetes control plane to operate over IPv6](#configure-the-kubernetes-control-plane-to-operate-over-ipv6)

#### Enable dual stack, Kubernetes

1. Set up a new cluster following the Kubernetes {% include open-new-window.html text='prerequisites' url='https://kubernetes.io/docs/concepts/services-networking/dual-stack/#prerequisites' %} and {% include open-new-window.html text='enablement steps' url='https://kubernetes.io/docs/concepts/services-networking/dual-stack/#enable-ipv4-ipv6-dual-stack' %}.

1. Using the [{{site.prodname}} Kubernetes install guide]({{site.baseurl}}/getting-started/kubernetes/self-managed-onprem/onpremises), download the right {{site.prodname}} manifest for the cluster, and datastore type.

1. Edit the CNI config (`calico-config` ConfigMap in the manifest), and enable IP address allocation by setting both modes to true.

   ```
       "ipam": {
           "type": "calico-ipam",
           "assign_ipv4": "true",
           "assign_ipv6": "true"
       },
   ```

1. Configure IPv6 **IP address autodetection** and **IP pool** by adding the following variable settings to the environment for the `calico-node` container:

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

#### Enable IPv6-only, initial manifest install

To configure IPv6-only support for Kubernetes during {{site.prodname}} installation, follow these steps.

1. Download the appropriate {{site.prodname}} manifest for IPv6 deployment and save it as `calico.yaml`.
1. Edit the `calico.yaml` ipam section, and modify it to [disable IPv4 assignments and enable IPv6 assignments](/reference/cni-plugin/configuration#ipam).
   ```
       "ipam": {
           "type": "calico-ipam",
           "assign_ipv4": "true",
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

#### Enable IPv6-only, initial install, Kubernetes

If you installed {{site.prodname}} on the cluster using the default IPv4, and you want switch to IPv6-only, or your hosts only have IPv6 addresses, follow these steps.

1. Disable [IP autodetection of IPv4]({{site.baseurl}}//networking/ip-autodetection) by setting `IP` to `none`.
1. Calculate the {{site.prodname}} BGP router ID for IPv6 using either of the following methods.
   - Set the environment variable `CALICO_ROUTER_ID=hash` on {{site.nodecontainer}}.
  This configures {{site.prodname}} to calculate the router ID based on the hostname, or
   - Pass a unique value for `CALICO_ROUTER_ID` to each node individually.
            |
4. If you are using [kube-dns](/getting-started/kubernetes/installation/manifests/kubedns.yaml), you may need to modify your DNS for IPv6 operation.

   - Update the image versions to at least `1.14.8`.
   - Ensure the clusterIP for the DNS service matches the one specified to the kubelet as `--cluster-dns`.
   - Add `--dns-bind-address=[::]` to the arguments for the kubedns container.
   - Add `--no-negcache` to the arguments for the dnsmasq container.
   - Switch the arguments on the sidecar container from

  ```
  --probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local,5,A
  --probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local,5,A
  ```
  {: .no-select-button}
  to
  ```
  --probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local,5,SRV
  --probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local,5,SRV
  ```
  {: .no-select-button}

#### Enable dual stack, OpenShift

TBD - operator steps

#### Enable IPv6-only, OpenShift

TBD - operator steps

#### (Optional) Configure the Kubernetes control plane to operate over IPv6

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
