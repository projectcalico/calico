---
title: Enabling IPv6 Support
redirect_from: latest/usage/ipv6
canonical_url: 'https://docs.projectcalico.org/v3.2/usage/ipv6'
---

### About enabling IPv6

After enabling IPv6:
- Workloads can communicate over IPv6.
- Workloads can initiate connections to IPv6 services.
- Workloads can terminate incoming IPv6 connections.

Support for IPv6 and the procedure for enabling it varies by orchestrator.
Refer to the section that corresponds to your orchestrator for details.

- [Enabling IPv6 with Kubernetes](#enabling-ipv6-with-kubernetes)
- [Enabling IPv6 with OpenStack](#enabling-ipv6-with-openstack)

## Enabling IPv6 with Kubernetes

### Limitations

- Currently Kubernetes supports only one IP stack version at a time. This
  means that if you configure Kubernetes for IPv6 then {{site.prodname}}
  should be configured to assign only IPv6 addresses.
- The steps and setup here have not been tested against an existing IPv4
  cluster and are intended only for new clusters.

### Prerequisites

#### Host prerequisites

- Each Kubernetes host must have an IPv6 address that is reachable from
  the other hosts.
- Each host must have the sysctl setting `net.ipv6.conf.all.forwarding`
  setting it to `1`.  This ensures both Kubernetes service traffic
  and {{site.prodname}} traffic is forwarded appropriately.
- Each host must have a default IPv6 route.

#### Kubernetes components prerequisites

Kubernetes components must be configured to operate with IPv6.
To enable IPv6, set the following flags.

##### kube-apiserver 

| Flag | Value/Content |
| ---- | ------------- |
| `--bind-address` or `--insecure-bind-address` | Should be set to the appropriate IPv6 address or `::` for all IPv6 addresses on the host. |
| `--advertise-address` | Should be set to the IPv6 address that nodes should use to access the kube-apiserver. |
| `--service-cluster-ip-range` | Should be set to an IPv6 CIDR that will be used for the Service IPs, the DNS service address must be in this range. |

##### kube-controller-manager

| Flag | Value/Content |
| ---- | ------------- |
| `--master` | Should be set with the IPv6 address where the kube-apiserver can be accessed. |
| `--node-cidr-mask-size` | If the `--allocate-node-cidrs` flag is set then it is necessary to set this flag, they are necessary when using host-local IPAM. If using calico-ipam is is easier to remove both flags as they are not needed. |
| `--cluster-cidr` | Should be set to match the {{site.prodname}} IPv6 IPPool. |

##### kube-scheduler

| Flag | Value/Content |
| ---- | ------------- |
| `--master` | Should be set with the IPv6 address where the kube-apiserver can be accessed. |

##### kubelet

| Flag | Value/Content |
| ---- | ------------- |
| `--address` | Should be set to the appropriate IPv6 address or `::` for all IPv6 addresses. |
| `--cluster-dns` | Should be set to the IPv6 address that will be used for the service DNS, this must be in the range used for `--service-cluster-ip-range`. |
| `--node-ip` | Should be set to the IPv6 address of the node. |

##### kube-proxy

| Flag | Value/Content |
| ---- | ------------- |
| `--bind-address` | Should be set to the appropriate IPv6 address or `::` for all IPv6 addresses on the host. |
| `--master` | Should be set with the IPv6 address where the kube-apiserver can be accessed. |
| `--cluster-cidr` | Should be set to match the {{site.prodname}} IPv6 IPPool. |

### Enabling IPv6 support in {{site.prodname}}

To enable IPv6 support when installing {{site.prodname}} follow the
steps below.

1. Download the {{site.prodname}} manifest you wish to update for IPv6
   deployment and save it as `calico.yaml`.
1. If the ipam section in the `cni_network_config` in the `calico.yaml` file
   has `"type": "calico-ipam"` then it should be modified to
   [disable IPv4 assignments and enable IPv6
   assigments](/{{page.version}}/reference/cni-plugin/configuration#ipam).
1. Add the following environment variables to the calico-node Daemonset in
   the `calico.yaml` file. Be sure to set the value for `CALICO_IPV6POOL_CIDR`
   to the desired pool, it should match the `--cluster-cidr` passed to the
   kube-controller-manager and to kube-proxy.

   ```
   - name: CALICO_IPV6POOL_CIDR
     value: "fd20::0/112"
   - name: IP6
     value: "autodetect"
   ```

1. Ensure in the `calico.yaml` file that the environment variable
   `FELIX_IPV6SUPPORT` is set `true` on the calico-node Daemonset.
1. Apply the `calico.yaml` manifest with `kubectl apply -f calico.yaml`.

#### Using only IPv6

If you wish to only use IPv6 (by disabling IPv4) or your hosts only have
IPv6 addresses, you must disable autodetection of IPv4 by setting `IP`
to `none`.  With that set you must also pass a `CALICO_ROUTER_ID` to each
calico-node pod.

### Modifying your DNS for IPv6

It will probably be necessary to modify your DNS pod for IPv6. If you are using
[kube-dns](/{{page.version}}/getting-started/kubernetes/installation/manifests/kubedns.yaml), 
then the following changes will ensure IPv6 operation.

- Update the image versions to at least `1.14.8`.
- Ensure the clusterIP for the DNS service matches the one specified to
  the kubelet as `--cluster-dns`.
- Add `--dns-bind-address=[::]` to the arguments for the kubedns container.
- Add `--no-negcache` to the arguments for the dnsmasq container.
- Switch the arguments on the sidecar container from
  ```
  --probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local,5,A
  --probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local,5,A
  ```
  to
  ```
  --probe=kubedns,127.0.0.1:10053,kubernetes.default.svc.cluster.local,5,SRV
  --probe=dnsmasq,127.0.0.1:53,kubernetes.default.svc.cluster.local,5,SRV
  ```

## Enabling IPv6 with OpenStack

### Prerequisites

When using {{site.prodname}} with a VM platform (e.g., OpenStack), obtaining IPv6
connectivity requires certain configuration in the guest VM image:

-  When it boots up, the VM should issue a DHCPv6 request for each of
   its interfaces, so that it can learn the IPv6 addresses that
   OpenStack has allocated for it.
-  The VM must be configured to accept router advertisements.
-  If the VM uses the widely deployed DHCP client from ISC, it must
   have a fix or workaround for [this known
   issue](https://kb.isc.org/article/AA-01141/31/How-to-workaround-IPv6-prefix-length-issues-with-ISC-DHCP-clients.html).

These requirements are not yet all met in common cloud images—but it
is easy to remedy that by launching an image, making appropriate changes
to its configuration files, taking a snapshot, and then using that
snapshot thereafter instead of the original image.

For example, starting from an Ubuntu cloud image, the following
changes will suffice to meet the requirements just listed.

-   In `/etc/network/interfaces.d/eth0.cfg`, add:

        iface eth0 inet6 dhcp
                accept_ra 1

-   In `/sbin/dhclient-script`, add at the start of the script:

        new_ip6_prefixlen=128

-   In `/etc/sysctl.d`, create a file named `30-eth0-rs-delay.conf` with
    contents:

        net.ipv6.conf.eth0.router_solicitation_delay = 10

For CentOS, these additions to a cloud-init script have been reported to be effective:

	runcmd:
	- sed -i -e '$a'"IPV6INIT=yes" /etc/sysconfig/network-scripts/ifcfg-eth0
	- sed -i -e '$a'"DHCPV6C=yes" /etc/sysconfig/network-scripts/ifcfg-eth0
	- sed -i '/PATH/i\new_ip6_prefixlen=128' /sbin/dhclient-script
	- systemctl restart network


### Enabling IPv6 support in {{site.prodname}}

In OpenStack, IPv6 connectivity requires defining an IPv6 subnet, in
each Neutron network, with:

-   the IPv6 address range that you want your VMs to use
-   DHCP enabled
-   (from Juno onwards) IPv6 address mode set to DHCPv6 stateful.

We suggest initially configuring both IPv4 and IPv6 subnets in each
network. This allows handling VM images that support only IPv4 alongside
those that support both IPv4 and IPv6, and allows a VM to be accessed
over IPv4 in case this is needed to troubleshoot any issues with its
IPv6 configuration.

In principle, though, we are not aware of any problems with configuring
and using IPv6-only networks in OpenStack.
