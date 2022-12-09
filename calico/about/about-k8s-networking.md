---
title: About Kubernetes Networking
description: Learn about Kubernetes networking!
canonical_url: 'https://www.tigera.io/learn/guides/kubernetes-networking/'
---

{% comment %}
Do not change the canonical_url above *or the title*. Content is shared with Marketing and is used for SEO purposes. If you change the title, it will mess up Marketing metrics. 
{% endcomment %}

> <span class="glyphicon glyphicon-info-sign"></span> This guide provides optional background education, not specific to {{site.prodname}}.
{: .alert .alert-info}

Kubernetes defines a network model that helps provide simplicity and consistency across a range of networking
environments and network implementations. The Kubernetes network model provides the foundation for understanding how
containers, pods, and services within Kubernetes communicate with each other. This guide explains the key concepts and
how they fit together. 

In this guide you will learn:
- The fundamental network behaviors the Kubernetes network model defines.
- How Kubernetes works with a variety of different network implementations.
- What Kubernetes Services are.
- How DNS works within Kubernetes.
- What "NAT outgoing" is and when you would want to use it.
- What "dual stack" is.

### The Kubernetes network model

The Kubernetes network model specifies:
- Every pod gets its own IP address
- Containers within a pod share the pod IP address and can communicate freely with each other
- Pods can communicate with all other pods in the cluster using pod IP addresses (without
  [NAT]({{site.baseurl}}/about/about-networking#nat))
- Isolation (restricting what each pod can communicate with) is defined using network policies

As a result, pods can be treated much like VMs or hosts (they all have unique IP addresses), and the containers within
pods very much like processes running within a VM or host (they run in the same network namespace and share an IP
address). This model makes it easier for applications to be migrated from VMs and hosts to pods managed by Kubernetes.
In addition, because isolation is defined using network policies rather than the structure of the network, the network
remains simple to understand. This style of network is sometimes referred to as a "flat network".

Note that, although very rarely needed, Kubernetes does also support the ability to map host ports through to pods, or
to run pods directly within the host network namespace sharing the host's IP address.

### Kubernetes network implementations

Kubernetes built in network support, kubenet, can provide some basic network connectivity. However, it is more common to
use third party network implementations which plug into Kubernetes using the CNI (Container Network Interface) API.

There are lots of different kinds of CNI plugins, but the two main ones are:
- network plugins, which are responsible for connecting pod to the network
- IPAM (IP Address Management) plugins, which are responsible for allocating pod IP addresses.

{{site.prodname}} provides both network and IPAM plugins, but can also integrate and work seamlessly with some other CNI
plugins, including AWS, Azure, and Google network CNI plugins, and the host local IPAM plugin. This flexibility allows
you to choose the best networking options for your specific needs and deployment environment. You can read more about
this in the {{site.prodname}} [determine best networking option]({{site.baseurl}}/networking/determine-best-networking)
guide.

### Kubernetes Services

Kubernetes {% include open-new-window.html text='Services' url='https://kubernetes.io/docs/concepts/services-networking/service/' %} provide a way of abstracting access to a group of pods as a network service.
The group of pods is usually defined using a {% include open-new-window.html text='label selector' url='https://kubernetes.io/docs/concepts/overview/working-with-objects/labels' %}.
Within the cluster the network service is usually represented as virtual IP address, and kube-proxy load balances connections to the virtual IP across the group of pods backing the service.
The virtual IP is discoverable through Kubernetes DNS.
The DNS name and virtual IP address remain constant for the life time of the service, even though the pods backing the service may be created or destroyed, and the number of pods backing the service may change over time.

Kubernetes Services can also define how a service is accessed from outside of the cluster, for example using
- a node port, where the service can be accessed via a specific port on every node
- or a load balancer, whether a network load balancer provides a virtual IP address that the service can be accessed via
  from outside the cluster.

Note that when using {{site.prodname}} in on-prem deployments you can also [advertise service IP
addresses]({{site.baseurl}}/networking/advertise-service-ips), allowing services to be conveniently accessed without
going via a node port or load balancer.

### Kubernetes DNS

Each Kubernetes cluster provides a DNS service. Every pod and every service is discoverable through the Kubernetes DNS
service.

For example:
- Service: `my-svc.my-namespace.svc.cluster-domain.example`
- Pod: `pod-ip-address.my-namespace.pod.cluster-domain.example`
- Pod created by a deployment exposed as a service:
  `pod-ip-address.deployment-name.my-namespace.svc.cluster-domain.example`.

The DNS service is implemented as Kubernetes Service that maps to one or more DNS server pods (usually CoreDNS), that
are scheduled just like any other pod. Pods in the cluster are configured to use the DNS service, with a DNS search list
that includes the pod's own namespace and the cluster's default domain.

This means that if there is a service named `foo` in Kubernetes namespace `bar`, then pods in the same namespace can
access the service as `foo`, and pods in other namespaces can access the service as `foo.bar`

Kubernetes supports a rich set of options for controlling DNS in different scenarios. You can read more about these in
the Kubernetes guide {% include open-new-window.html text='DNS for Services and Pods'
url='https://kubernetes.io/docs/concepts/services-networking/dns-pod-service/' %}.

### NAT outgoing

The Kubernetes network model specifies that pods must be able to communicate with each other directly using pod IP
addresses. But it does not mandate that pod IP addresses are routable beyond the boundaries of the cluster. Many
Kubernetes network implementations use [overlay networks]({{site.baseurl}}/about/about-networking#overlay-networks).
Typically for these deployments, when a pod initiates a connection to an IP address outside of the cluster, the node
hosting the pod will SNAT (Source Network Address Translation) map the source address of the packet from the pod IP to
the node IP. This enables the connection to be routed across the rest of the network to the destination (because the
node IP is routable). Return packets on the connection are automatically mapped back by the node replacing the node IP
with the pod IP before forwarding the packet to the pod.

When using {{site.prodname}}, depending on your environment, you can generally choose whether you prefer to run an
overlay network, or prefer to have fully routable pod IPs. You can read more about this in the {{site.prodname}}
[determine best networking option]({{site.baseurl}}/networking/determine-best-networking) guide. {{site.prodname}} also
allows you to [configure outgoing NAT]({{site.baseurl}}/networking/workloads-outside-cluster) for specific IP address
ranges if more granularity is desired.

### Dual stack

If you want to use a mix of IPv4 and IPv6 then you can enable Kubernetes {% include open-new-window.html
text='dual-stack' url='https://kubernetes.io/docs/concepts/services-networking/dual-stack/' %} mode. When enabled, all
pods will be assigned both an IPv4 and IPv6 address, and Kubernetes Services can specify whether they should be exposed
as IPv4 or IPv6 addresses.

### Above and beyond

- {% include open-new-window.html text='The Kubernetes Network Model'
  url='https://kubernetes.io/docs/concepts/cluster-administration/networking/#the-kubernetes-network-model' %} 
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes networking on AWS'
  url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-pod-networking-on-aws/' %}
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes networking on Azure'
  url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-networking-on-azure/' %}
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes networking on Google Cloud'
  url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-networking-on-google-cloud/' %}

