---
title: About Kubernetes Services
description: Learn about Kubernetes services!
---

> <span class="glyphicon glyphicon-info-sign"></span> This guide provides optional background education, including
> education that is not specific to {{site.prodname}}.
{: .alert .alert-info}

In this guide you will learn:
- What are Kubernetes Services?
- What are the differences between the three main service types and what do you use them for?
- How do services and network policy interact?
- Some options for optimizing how services are handled.

### What are Kubernetes Services?

Kubernetes {% include open-new-window.html text='Services'
url='https://kubernetes.io/docs/concepts/services-networking/service/' %} provide a way of abstracting access to a group
of pods as a network service. The group of pods backing each service is usually defined using a {% include
open-new-window.html text='label selector'
url='https://kubernetes.io/docs/concepts/overview/working-with-objects/labels' %}. 

When a client connects to a Kubernetes service, the connection is load balanced to one of the pods backing the service,
as illustrated in this conceptual diagram:

![Kubernetes Service conceptual diagram]({{site.baseurl}}/images/k8s-service-concept.svg)

There are three main types of Kubernetes services:
- Cluster IP - which is the usual way of accessing a service from inside the cluster
- Node port - which is the most basic way of accessing a service from outside the cluster
- Load balancer - which uses an external load balancer as a more sophisticated way to access a service from outside the
  cluster.

### Cluster IP services

The default service type is `ClusterIP`. This allows a service to be accessed within the cluster via a virtual IP
address, known as the service Cluster IP. The Cluster IP for a service is discoverable through Kubernetes DNS. For
example, `my-svc.my-namespace.svc.cluster-domain.example`. The DNS name and Cluster IP address remain constant for the
life time of the service, even though the pods backing the service may be created or destroyed, and the number of pods
backing the service may change over time.

In a typical Kubernetes deployment, kube-proxy runs on every node and is responsible for intercepting connections to
Cluster IP addresses and load balancing across the group of pods backing each service. As part of this process
[DNAT]({{site.baseurl}}/about/about-networking#nat) is used to map the destination IP address from the Cluster IP to the
chosen backing pod. Response packets on the connection then have the NAT reverse on their way back to the pod that
initiated the connection.

![kube-proxy cluster IP]({{site.baseurl}}/images/kube-proxy-cluster-ip.svg)

Importantly, network policy is enforced based on the pods, not the service Cluster IP.  (i.e. Egress network policy is
enforced for the client pod after the DNAT has changed the connection's destination IP to the chosen service backing
pod. And because only the destination IP for the connection is changed, ingress network policy for the backing pod sees the
original client pod as the source of the connection.)

### Node port services

The most basic way to access a service from outside the cluster is to use a service of type `NodePort`. A Node Port is a
port reserved on each node in the cluster through which the service can be accessed. In a typical Kubernetes deployment,
kube-proxy is responsible for intercepting connections to Node Ports and load balancing them across the pods backing
each service.  

As part of this process [NAT]({{site.baseurl}}/about/about-networking#nat) is used to map the destination IP address and
port from the node IP and Node Port, to the chosen backing pod and service port. In addition the source IP address is
mapped from the client IP to the node IP, so that response packets on the connection flow back via the original node,
where the NAT can be reversed. (It's the node which performed the NAT that has the connection tracking state needed to
reverse the NAT.)

![kube-proxy node port]({{site.baseurl}}/images/kube-proxy-node-port.svg)

Note that because the connection source IP address is SNATed to the node IP address, ingress network policy for the
service backing pod does not see the original client IP address. Typically this means that any such policy is limited to
restricting the destination protocol and port, and cannot restrict based on the client / source IP. This limitation can
be circumvented in some scenarios by using [externalTrafficPolicy](#externaltrafficpolicylocal) or by using
{{site.prodname}}'s eBPF dataplane [native service handling](#calico-ebpf-native-service-handling) (rather than kube-proxy) which preserves source IP address.

### Load balancer services

Services of type `LoadBalancer` expose the service via an external network load balancer (NLB). The exact type of
network load balancer depends on which public cloud provider or, if on-prem, which specific hardware load balancer integration is
integrated with your cluster.

The service can be accessed from outside of the cluster via a specific IP address on the network load balancer, which by
default will load balance evenly across the nodes using the service node port.

![kube-proxy load balancer]({{site.baseurl}}/images/kube-proxy-load-balancer.svg)

Most network load balancers preserve the client source IP address, but because the service then goes via a node port,
the backing pods themselves do not see the client IP, with the same implications for network policy.  As with node
ports, this limitation can be circumvented in some scenarios by using [externalTrafficPolicy](#externaltrafficpolicylocal)
or by using {{site.prodname}}'s eBPF dataplane [native service handling](#calico-ebpf-native-service-handling) (rather
than kube-proxy) which preserves source IP address.

### Advertising service IPs

One alternative to using node ports or network load balancers is to advertise service IP addresses over BGP. This
requires the cluster to be running on an underlying network that supports BGP, which typically means an on-prem
deployment with standard Top of Rack routers.

{{site.prodname}} supports advertising service Cluster IPs, or External IPs for services configured with one. If you are
not using Calico as your network plugin then {% include open-new-window.html text='MetalLB'
url='https://github.com/metallb/metallb' %} provides similar capabilities that work with a variety of different network
plugins.

![kube-proxy service advertisement]({{site.baseurl}}/images/kube-proxy-service-advertisement.svg)

### externalTrafficPolicy:local

By default, whether using service type `NodePort` or `LoadBalancer` or advertising service IP addresses over BGP,
accessing a service from outside the cluster load balances evenly across all the pods backing the service, independent
of which node the pods are on. This behavior can be changed by configuring the service with
`externalTrafficPolicy:local` which specifies that connections should only be load balanced to pods backing the service
on the local node.

When combined with services of type `LoadBalancer` or with {{site.prodname}} service IP address advertising, traffic is
only directed to nodes that host at least one pod backing the service. This reduces the potential extra network hop
between nodes, and perhaps more importantly, to maintain the source IP address all the way to the pod, so network policy
can restrict specific external clients if desired.

![kube-proxy service advertisement]({{site.baseurl}}/images/kube-proxy-service-local.svg)

Note that in the case of services of type `LoadBalancer`, not all Load Balancers support this mode. And in the case of
service IP advertisement, the evenness of the load balancing becomes topology dependent. In this case, pod anti-affinity
rules can be used to ensure even distribution of backing pods across your topology, but this does add some complexity to
deploying the service.

### Calico eBPF native service handling

As an alternative to using Kubernetes standard kube-proxy, {{site.prodname}}'s [eBPF
dataplane]({{site.baseurl}}/maintenance/ebpf/enabling-ebpf) supports native service handling. This preserves source IP to
simplify network policy, offers DSR (Direct Server Return) to reduce the number of network hops for return traffic, and
provides even load balancing independent of topology, with reduced CPU and latency compared to kube-proxy.

![kube-proxy service advertisement]({{site.baseurl}}/images/calico-native-service-handling.svg)

## Above and beyond

- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes Services networking   '
  url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-services-networking/' %}
- {% include open-new-window.html text='Blog: Introducing the Calico eBPF dataplane'
  url='https://www.projectcalico.org/introducing-the-calico-ebpf-dataplane/' %}
- {% include open-new-window.html text='Blog: Hands on with Calico eBPF native service handling'
  url='https://www.projectcalico.org/hands-on-with-calicos-ebpf-service-handling/' %}






