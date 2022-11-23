---
title: VPP dataplane implementation details
description: Technical details on the VPP dataplane integration.
canonical_url: '/reference/vpp/technical-details'
---

### Software architecture

The VPP dataplane integration is split in two components, `vpp-manager` which handles the VPP startup configuration and lifecycle; and `calico-vpp-agent` which is responsible for all the runtime configuration of VPP for {{ site.prodname }}. Both processes run in separate containers in the calico-vpp-node pod, which runs in the host's root network namespace.

![Implementation architecture]({{ site.baseurl }}/images/vpp-soft-arch.svg)

#### vpp-manager

VPP Manager is a very light process responsible for the bootstrap of VPP, including uplink interface addressing and routing configuration. It also restores the Linux configuration on shutdown. The code can be found in this directory: [https://github.com/projectcalico/vpp-dataplane/tree/{{page.vppbranch}}/vpp-manager](https://github.com/projectcalico/vpp-dataplane/tree/{{page.vppbranch}}/vpp-manager).

On startup, vpp-manager starts by determining the desired configuration for the VPP uplink by checking it's configuration in Linux, including addresses and routes. It then renders an appropriate configuration file for VPP, and starts the VPP process.

Once VPP is running, vpp-manager connects to it using the API and starts configuring the uplink interface as it was configured in Linux. Once this is done, it configures a tap interface in the host to restore its connectivity.

Once it is running, vpp-manager forwards all received Unix signals to VPP to handle stops gracefully.

When VPP stops, either in reaction to a received signal or in case of a crash, vpp-manager restores the configuration of the Linux interface so that the host recovers its connectivity to the outside through the original uplink interface.

vpp-manager is voluntarily kept as simple as possible, in order to minimize the risk of bugs, as these could leave the host without connectivity, requiring a reboot.

#### calico-vpp-agent

The {{ site.prodname }} VPP agent is the process responsible for all the {{ site.prodname }}-specific configuration in VPP. Its code lives in this directory: [https://github.com/projectcalico/vpp-dataplane/tree/{{page.vppbranch}}/calico-vpp-agent](https://github.com/projectcalico/vpp-dataplane/tree/{{page.vppbranch}}/calico-vpp-agent).

This agent is split in four main components, which interact with the k8s and {{ site.prodname }} APIs to configure VPP. These components are the routing manager, the CNI server, the services manager and the policies manager.

**Routing manager**

The {{ site.prodname }} VPP agent embeds a GoBGP daemon, and dynamically updates its configuration (including peers, ASN, etc.) according to the {{ site.prodname }} configuration. As the calico-vpp-node pod runs in the host network namespace, the BGP daemon uses the host's TCP stack, and sends and receives traffic through the host's interface `vpptap0`.

When routes are added or removed in BGP, the routing manager reflects the changes in VPP. The routes are installed differently depending on the {{ site.prodname }} configuration. If the configuration requires the use of an IPIP or VXLAN tunnel, then the tunnel interface will be created on demand in VPP, and the route will be added through the tunnel. Otherwise, the route is simply added as-is in VPP.

**CNI server**

This component implements a server that receives gRPC request from the {{ site.prodname }} CNI (configured with a gRPC dataplane) through a Unix socket mounted on the host.

When it receives an ADD request, the CNI server creates a tap interface in the container's namespace, and configures it with the IP address and routes chosen by {{ site.prodname }}. The routes' next hop is an otherwise unused link-local address, both in IPv4 and in IPv6. A /32 or /128 route is added in VPP as well for the container address through the tap. When it receives a DEL request, the CNI servers cleans up the tap from VPP and from the container's namespace.

**Services manager**

This component is the equivalent of kube-proxy for VPP, i.e. it configures NAT load-balancing rules to implement Kubernetes services in VPP. It watches the Kubernetes Services and Endpoints APIs, and updates the VPP configuration on each change. Service load balancing is implemented with a {{ site.prodname }}-specific DNAT plugin in VPP.

**Policies manager**

This component implements {{ site.prodname }} policies in VPP. Felix ({{ site.prodname }}'s policy agent) is configured to use a lightweight proxy as its dataplane. This proxy relays all the configuration messages sent by Felix to the `calico-vpp-agent`, and status updates the other way. The VPP agent then uses a custom plugin in VPP to implement policies.

### Network architecture

#### Primary interface configuration

In order to send and receive the packets on behalf on the containers, VPP needs to use one of the host's network interfaces. There are various ways to do so, which differ in performance and configuration complexity:
- AF_PACKET: the slowest option, but also the most universally supported one as it works for every Linux network device. The interface is placed in a dedicated network namespace in order not to disrupt the host connectivity that is set up by VPP.
- AF_XDP: much more performant than AF_PACKET, but it requires a recent kernel version (5.4+). The interface is placed in a dedicated network namespace in order not to disrupt the host connectivity that is set up by VPP.
- DPDK: VPP can use DPDK to drive interfaces. This is more performant than AF_XDP. DPDK supports a large number of interfaces, but requires hugepages to be configured on the host to work. The interface is bound to a specific PCI driver on startup, and thus disappears from the host's kernel network devices.
- VPP native drivers: the most performant option, but a limited number of interfaces are supported. Supported interfaces include Intel AVF, Mellanox Connect-X series, vmxnet3 (VMware) interfaces, and virtio (use by Qemu/KVM and GCE) interfaces. As with DPDK, the interface needs to be bound to a specific PCI driver on startup, and thus disappears from the host. Using native drivers requires custom configuration, except for `virtio` and Intel AVF interfaces which are supported by `vpp-manager`.

#### Host network configuration

See the [dedicated page]({{ site.baseurl }}/reference/vpp/host-network).

#### Container interfaces

When a Pod is scheduled on the host, the kubelet service will create the network namespace for the new pod, and then use the CNI to request that {{ site.prodname }} configures an interface in this namespace. {{ site.prodname }} will first compute the IP configuration for the host (address and routes), and then pass that to the VPP agent. VPP will then create a tun interface in the desired namespace for the container, and configure it with the required address and routes. This makes all the container traffic flow through VPP.

#### Container routing & services load balancing

To determine the host where each pod is running, {{ site.prodname }} uses BGP. Routes learned from BGP are installed in VPP in order to reach the containers that are running on other nodes. Depending on the {{ site.prodname }} configuration, these routes are either to directly connected hosts, or through tunnel interfaces if encapsulation is required.

Services load balancing is implemented with NAT rules in VPP, in a very similar way to what kube-proxy is doing. The source address is preserved when possible for external connections.

Here is the resulting logical network topology:

![Network architecture]({{ site.baseurl }}/images/vpp-net-arch.svg)

