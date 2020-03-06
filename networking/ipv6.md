---
title: Configure IPv6 and IPv4 modes
description: Configure IPv6, IPv4 or both modes (dual stack) IP modes for workloads.
canonical_url: '/networking/ipv6'
---

### Big picture

Configure {{site.prodname}} IP address allocation mode (IPv6, IPv4, or both) for workload communications.

### Value

Although communication over IPv6 is increasingly desirable as the natural mode for workloads, it still often a requirement to continue support for IPv4. {{site.prodname}} supports using both protocols (called "dual stack"), as well as IPv6-only, and the default IPv4. 

### Features

This how-to guide uses the following {{site.prodname}} features:

- [**CNI plugin configuration**]({{ site.baseurl }}/reference/cni-plugin/configuration#ipam) with `assign_ipv6` and `assign_ipv4` flags

### Before you begin...

**{{site.prodname}} requirements**
  You must be using {{site.prodname}} IPAM. The defaut mode is IPv4 (CNI ConfigMap manifest with `assign_ipv4: true`).

**Kubernetes support**
  - 1.16 and 1.17 support dual stack (alpha-level)
  - 1.15 and earlier support using one IP stack at a time (IPv6 or IPv4).  
    For example, if you configure Kubernetes for IPv6, you must configure {{site.prodname}} to assign only IPv6 addresses.

**Kubernetes IPv6 host requirements**
  - An IPv6 address that is reachable from the other hosts
  - The sysctl setting `net.ipv6.conf.all.forwarding` setting it to `1`.    
    This ensures both Kubernetes service traffic and {{site.prodname}} traffic is forwarded appropriately.
  - A default IPv6 route

### How to

>**Note**: All steps assume **new clusters** (not existing IPv4 clusters). 
{: .alert .alert-info}

**Kubernetes**
- [Configure dual stack](#configure-dual-stack)
- [Configure IPv6-only, during installation](#configure-ipv6-only-during-installation)
- [Configure IPv6-only, after installation](#configure-ipv6-only-after-installation)

**OpenStack**
- [Configure OpenStack for IPv6, IPv4, or dual stack](#configure-openstack-for-ipv6-ipv4-or-dual-stack)

#### Configure dual stack

To configure dual stack for Kubernetes, follow these steps: 

1. Set up a new cluster following the Kubernetes {% include open-new-window.html text='prerequisites' url='https://kubernetes.io/docs/concepts/services-networking/dual-stack/#prerequisites' %} and {% include open-new-window.html text='enablement steps' url='https://kubernetes.io/docs/concepts/services-networking/dual-stack/#enable-ipv4-ipv6-dual-stack' %}.

1. Using the {{site.prodname}}[Install guide for Kubernetes]({{site.baseurl}}/getting-started/kubernetes/self-managed-onprem/onpremises), download the right {{site.prodname}} manifest for the cluster, and your preferred datastore type. 

1. Edit the CNI config (`calico-config` ConfigMap in the manifest), and enable IP address allocation by setting both modes to true.

   ```
       "ipam": {
           "type": "calico-ipam",
           "assign_ipv4": "true",
           "assign_ipv6": "true"
       },
   ```

1. Add the following variable settings to the environment for the `calico-node` container:

   | Variable name | Value |
   | ------------- | ----- |
   | `IP6`         | `autodetect` |
   | `CALICO_IPV6POOL_CIDR` | the same as the IPv6 range you configured as the cluster CIDR to kube-controller-manager and kube-proxy |
   | `FELIX_IPV6SUPPORT` | `true` |

1. Apply the edited manifest with `kubectl apply -f`.
   New pods will get IPv6 addresses as well as IPv4, and can communicate with each other and the outside world over IPv6.

#### Configure IPv6-only, during installation

To configure IPv6-only support for Kubernetes during {{site.prodname}} installation, follow these steps.

1. Download the appropriate {{site.prodname}} manifest for IPv6 deployment and save it as `calico.yaml`.
1. Edit the `calico.yaml` ipam section, and modify it to [disable IPv4 assignments and enable IPv6 assigments](/reference/cni-plugin/configuration#ipam).
   ```
       "ipam": {
           "type": "calico-ipam",
           "assign_ipv4": "true",
           "assign_ipv6": "true"
       },
   ```
1. Add the following environment variables to the calico-node Daemonset in the `calico.yaml` file.   
Be sure to set the value for `CALICO_IPV6POOL_CIDR` to the desired pool; it should match the `--cluster-cidr` passed to the kube-controller-manager and to kube-proxy.

   ```yaml
   - name: CALICO_IPV6POOL_CIDR
     value: "fd20::0/112"
   - name: IP6
     value: "autodetect"
   ```

1. In the `calico.yaml` file, verify that the environment variable `FELIX_IPV6SUPPORT` is set `true` on the calico-node Daemonset.
1. Apply the `calico.yaml` manifest with `kubectl apply -f calico.yaml`.

#### Configure IPv6-only, after installation

If you installed {{site.prodname}} on the cluster using the default IPv4, but you want switch to IPv6-only, or your hosts only have IPv6 addresses, follow these steps.

1. Disable [IP autodetection of IPv4]({{site.baseurl}}//networking/ip-autodetection) by setting `IP` to `none`.

1. Calculate the {{site.prodname}} BGP router ID for IPv6 using either of the following methods.  

  - Set the environment variable `CALICO_ROUTER_ID=hash` on {{site.nodecontainer}}. This configures {{site.prodname}} to calculate the router ID based on the hostname.
  or
  - Pass a unique value for `CALICO_ROUTER_ID` to each node individually.

1. Configure Kubernetes components to enable IPv6 using the following flags.

   **kube-apiserver**

   | Flag | Value/Content |
   | ---- | ------------- |
   | `--bind-address` or `--insecure-bind-address` | Set to the appropriate IPv6 address or `::` for all IPv6 addresses on the host. |
   | `--advertise-address` | Set to the IPv6 address that nodes should use to access the kube-apiserver. |
   | `--service-cluster-ip-range` | Set to an IPv6 CIDR that will be used for the Service IPs, the DNS service address must be in this range. |

   **kube-controller-manager**

   | Flag | Value/Content |
   | ---- | ------------- |
   | `--master` | Set with the IPv6 address where the kube-apiserver can be accessed. |
   | `--cluster-cidr` | Set to match the {{site.prodname}} IPv6 IPPool. |

   **kube-scheduler**

   | Flag | Value/Content |
   | ---- | ------------- |
   | `--master` | Set with the IPv6 address where the kube-apiserver can be accessed. |

   **kubelet**

   | Flag | Value/Content |
   | ---- | ------------- |
   | `--address` | Set to the appropriate IPv6 address or `::` for all IPv6 addresses. |
   | `--cluster-dns` | Set to the IPv6 address that will be used for the service DNS, this must be in the range used for `--service-cluster-ip-range`. |
   | `--node-ip` | Set to the IPv6 address of the node. |

   **kube-proxy**

   | Flag | Value/Content |
   | ---- | ------------- |
   | `--bind-address` | Set to the appropriate IPv6 address or `::` for all IPv6 addresses on the host. |
   | `--master` | Set with the IPv6 address where the kube-apiserver can be accessed. |
   | `--cluster-cidr` | Set to match the {{site.prodname}} IPv6 IPPool. |
   

1. If you are using [kube-dns](/getting-started/kubernetes/installation/manifests/kubedns.yaml), you must modify your DNS for IPv6 operation.

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

#### Configure OpenStack for IPv6, IPv4, or dual stack

OpenStack controls whether a VM gets IPv4, IPv6, or both addresses, not {{site.prodname}}. Calico simply honors the addresses that OpenStack specifies. The following extra steps are required for IPv6-only or dual stack deployments -- so the guest OS can learn its IPv6 address if assigned by OpenStack.

1. Verify that the guest VM image meets these requirements for IPv6 connectivity.   

    - When booting up, the VM must issue a DHCPv6 request for each of its interfaces, so that it can learn the IPv6 addresses that OpenStack allocates for it. If the VM uses the widely-deployed **DHCP client from ISC**, it must have a fix/workaround for {% include open-new-window.html text='this known issue' url='https://kb.isc.org/article/AA-01141/31/How-to-workaround-IPv6-prefix-length-issues-with-ISC-DHCP-clients.html' %}. 
    - The VM must be configured to accept router advertisements. 

   Although not all common cloud images meet these requirements yet, it is easy to remedy by launching an image, making appropriate changes to its configuration files, taking a snapshot, and then using the snapshot thereafter instead of the original image.

   For example, starting from an **Ubuntu cloud image**, the following changes meet the requirements listed.

   -   In `/etc/network/interfaces.d/eth0.cfg`, add:
   
           iface eth0 inet6 dhcp
                   accept_ra 1
   
   -   In `/sbin/dhclient-script`, add at the start of the script:
   
           new_ip6_prefixlen=128
   
   -   In `/etc/sysctl.d`, create a file named `30-eth0-rs-delay.conf` with
       contents:
   
           net.ipv6.conf.eth0.router_solicitation_delay = 10

   For **CentOS**, these additions to a cloud-init script have been reported to be effective:

     runcmd:
     - sed -i -e '$a'"IPV6INIT=yes" /etc/sysconfig/network-scripts/ifcfg-eth0
     - sed -i -e '$a'"DHCPV6C=yes" /etc/sysconfig/network-scripts/ifcfg-eth0
     - sed -i '/PATH/i\new_ip6_prefixlen=128' /sbin/dhclient-script
     - systemctl restart network

1. Configure IPv6 support in {{site.prodname}} by defining an IPv6 subnet in each Neutron network with:

   - The IPv6 address range that you want your VMs to use
   - DHCP enabled
   - From Juno onwards, IPv6 address mode set to DHCPv6 stateful

   We suggest that you initially configure both IPv4 and IPv6 subnets in each network. This allows handling VM images that support only IPv4 alongside those that support both IPv4 and IPv6, and allows a VM to be accessed over IPv4 in case this is needed to troubleshoot any issues with its IPv6 configuration. In principle, though, we are not aware of any problems with configuring and using IPv6-only networks in OpenStack.
