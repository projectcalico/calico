---
title: About eBPF
description: Learn about eBPF!
canonical_url: 'https://www.tigera.io/learn/guides/ebpf/'
---

{% comment %}
Do not change the canonical_url above *or the title*. Content is shared with Marketing and is used for SEO purposes. If you change the title, it will mess up Marketing metrics. 
{% endcomment %}

> <span class="glyphicon glyphicon-info-sign"></span> This guide provides optional background education, including
> education that is not specific to {{site.prodname}}.
{: .alert .alert-info}

eBPF is a Linux kernel feature that allows fast yet safe mini-programs to be loaded into the kernel in order to
customise its operation.

In this guide you will learn:

- General background on eBPF.
- Various uses of eBPF.
- How {{site.prodname}} uses eBPF in the eBPF dataplane.

### What is eBPF?

eBPF is a virtual machine embedded within the Linux kernel.  It allows small programs to be loaded into the kernel,
and attached to hooks, which are triggered when some event occurs. This allows the behaviour of the kernel to be
(sometimes heavily) customised. While the eBPF virtual machine is the same for each type of hook, the capabilities
of the hooks vary considerably. Since loading programs into the kernel could be dangerous; the kernel runs all
programs through a very strict static verifier; the verifier sandboxes the program, ensuring it can only access
allowed parts of memory and ensuring that it must terminate quickly.

### Why is it called eBPF?

eBPF stands for "extended Berkeley Packet Filter". The Berkeley Packet Filter was an earlier, more specialised
virtual machine that was tailored for filtering packets. Tools such as `tcpdump` use this "classic" BPF VM to select
packets that should be sent to userspace for analysis. eBPF is a considerably extended version of BPF that
is suitable for general purpose use inside the kernel. While the name has stuck, eBPF can be used for a lot more
than just packet filtering.

### What can eBPF do?

#### Types of eBPF program

There are several classes of hooks to which eBPF programs can be attached within the kernel.  The capabilities of an
eBPF program depend hugely on the hook to which it is attached:

* **Tracing** programs can be attached to a significant proportion of the functions in the kernel.  Tracing
  programs are useful for collecting statistics and deep-dive debugging of the kernel.  *Most* tracing hooks only allow
  read-only access to the data that the function is processing but there are some that allow data to be modified.
  The {{site.prodname}} team use tracing programs to help debug {{site.prodname}} during development; for example,
  to figure out why the kernel unexpectedly dropped a packet.

* **Traffic Control** (`tc`) programs can be attached at ingress and egress to a given network device.  The kernel
  executes the programs once for each packet.  Since the hooks are for packet processing, the kernel allows
  the programs to modify or extend the packet, drop the packet, mark it for queueing, or redirect the packet to
  another interface.  {{site.prodname}}'s eBPF dataplane is based on this type of hook; we use tc programs to load
  balance Kubernetes services, to implement network policy, and, to create a fast-path for traffic of established
  connections.

* **XDP**, or "eXpress Data Path", is actually the name of an eBPF hook.  Each network device has an XDP ingress hook
  that is triggered once for each incoming packet before the kernel allocates a socket buffer for the packet.  XDP
  can give outstanding performance for use cases such as DoS protection (as supported in {{site.prodname}}'s standard Linux
  dataplane) and ingress load balancing (as used in facebook's Katran).  The downside of XDP is that it requires
  network device driver support to get good performance.  XDP isn't sufficient on its own to implement all of the logic
  needed for Kubernetes pod networking, but a combination of XDP and Traffic Control hooks works well.

* Several types of **socket** programs hook into various operations on sockets, allowing the eBPF program to, for
  example, change the destination IP of a newly-created socket, or force a socket to bind to the "correct" source
  IP address.  {{site.prodname}} uses such programs to do connect-time load balancing of Kubernetes Services; this
  reduces overhead because there is no [DNAT](./about-networking#NAT) on the packet processing path.

* There are various security-related hooks that allow for program behaviour to be policed in various ways. For
  example, the **seccomp** hooks allow for syscalls to be policed in fine-grained ways.

* And... probably a few more hooks by the time you read this; eBPF is under heavy development in the kernel.

The kernel exposes the capabilities of each hook via "helper functions". For example, the `tc` hook has a helper
function to resize the packet, but that helper would not be available in a tracing hook. One of the challenges of
working with eBPF is that different kernel versions support different helpers and lack of a helper can make it
impossible to implement a particular feature.

#### BPF maps

Programs attached to eBPF hooks are able to access BPF "maps". BPF maps have two main uses:

* They allow BPF programs to store and retrieve long-lived data.

* They allow communication between BPF programs and user-space programs.  BPF programs can read data that was written
  by userspace and vice versa.

There are many types of BPF maps, including some special types that allow jumping between programs, and, some that act
as queues and stacks rather than strictly as key/value maps. {{site.prodname}} uses maps to keep track of active
connections, and, to configure the BPF programs with policy and service NAT information.  Since map accesses can be
relatively expensive, {{site.prodname}} aims to do a single map lookup only for each packet on an established flow.

The contents of bpf maps can be inspected using the command-line tool, `bpftool`, which is provided with the kernel.

### {{site.prodname}}'s eBPF dataplane

{{site.prodname}}'s eBPF dataplane is an alternative to our standard Linux dataplane (which is iptables based).
While the standard dataplane focuses on compatibility by inter-working with kube-proxy, and your own iptables rules,
the eBPF dataplane focuses on performance, latency and improving user experience with features that aren't possible
in the standard dataplane. As part of that, the eBPF dataplane replaces kube-proxy with an eBPF implementation.
The main "user experience" feature is to preserve the source IP of traffic from outside the cluster when traffic hits a
NodePort; this makes your server-side logs and network policy much more useful on that path.

#### Feature comparison

While the eBPF dataplane has some features that the standard Linux dataplane lacks, the reverse is also true:

| Factor                    | Standard Linux Dataplane                | eBPF dataplane                     |
|---------------------------|-----------------------------------------|------------------------------------|
| Throughput                | Designed for 10GBit+                    | Designed for 40GBit+               |
| First packet latency      | Low (kube-proxy service latency is  bigger factor) | Lower                   |
| Subsequent packet latency | Low                                     | Lower                              |
| Preserves source IP within cluster | Yes                            | Yes                                |
| Preserves external source IP | Only with `externalTrafficPolicy: Local` | Yes                            |
| Direct Server Return      | Not supported                           | Supported (requires compatible underlying network) |
| Connection tracking       | Linux kernel's conntrack table (size can be adjusted) | BPF map (fixed size) |
| Policy rules              | Mapped to iptables rules                | Mapped to BPF instructions         |
| Policy selectors          | Mapped to IP sets                       | Mapped to BPF maps                 |
| Kubernetes services       | kube-proxy iptables or IPVS mode        | BPF program and maps               |
| IPIP                      | Supported                               | Supported (no performance advantage due to kernel limitations) |
| VXLAN                     | Supported                               | Supported                          |
| Wireguard                 | Supported (IPv4 and IPv6)               | Supported (IPv4)                   |
| Other routing             | Supported                               | Supported                          |
| Supports third party CNI plugins | Yes (compatible plugins only)    | Yes (compatible plugins only)      |
| Compatible with other iptables rules | Yes (can write rules above or below other rules) | Partial; iptables bypassed for workload traffic |
| Host endpoint policy      | Supported                               | Supported                          |
| Enterprise version        | Available                               | Available                          |
| XDP DoS Protection        | Supported                               | Supported                          |
| IPv6                      | Supported                               | Not supported (yet)                |

#### Architecture overview

{{site.prodname}}'s eBPF dataplane attaches eBPF programs to the `tc` hooks on each {{site.prodname}} interface as
well as your data and tunnel interfaces.  This allows {{site.prodname}} to spot workload packets early and handle them
through a fast-path that bypasses iptables and other packet processing that the kernel would normally do.

![Diagram showing the packet path for pod-to-pod networking; a BPF program is attached to the client pod's veth interface; it does a conntrack lookup in a BPF map, and forwards the packet to the second pod directly, bypassing iptables]({{site.baseurl}}/images/bpf-pod-to-pod.svg "Pod-to-pod packet path with eBPF enabled")

The logic to implement load balancing and packet parsing is pre-compiled ahead of time and relies on a set of BPF
maps to store the NAT frontend and backend information.  One map stores the metadata of the service, allowing
for `externalTrafficPolicy` and "sticky" services to be honoured. A second map stores the IPs of the backing pods.

In eBPF mode, {{site.prodname}} converts your policy into optimised eBPF bytecode, using BPF maps to store the IP sets
matched by policy selectors.

![Detail of BPF program showing that packets are sent to a separate (generated) policy program,]({{site.baseurl}}/images/bpf-policy.svg "Expanded view of tc program showing policy.")

To improve performance for services, {{site.prodname}} also does connect-time load balancing by hooking into the
socket BPF hooks.  When a program tries to connect to a Kubernetes service, {{site.prodname}} intercepts the connection
attempt and configures the socket to connect directly to the backend pod's IP instead.  This removes _all_
NAT overhead from service connections.

![Diagram showing BPF program attached to socket connect call; it does NAT at connect time,]({{site.baseurl}}/images/bpf-connect-time.svg "BPF program attached to socket connect call.")

### Above and beyond

* For more information and performance metrics for the eBPF dataplane, see the [announcement blog post](https://www.projectcalico.org/introducing-the-calico-ebpf-dataplane/).
* If you'd like to try eBPF mode in your Kubernetes cluster, follow the [Enable the eBPF dataplane]({{site.baseurl}}/maintenance/ebpf/enabling-ebpf) guide.
