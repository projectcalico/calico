---
title: About Kubernetes egress
description: Learn about Kubernetes egress!
---

> <span class="glyphicon glyphicon-info-sign"></span> This guide provides optional background education, including
> education that is not specific to {{site.prodname}}.
{: .alert .alert-info}

In this guide you will learn:
- What is Kubernetes egress?
- Why should you restrict egress traffic and how can you do it?
- What is "NAT outgoing" and when is it used?
- What is an egress gateway, and why might you want to use one?

### What is Kubernetes egress?

In this guide we are using the term Kubernetes egress to describe connections being made from pods to anything outside of the cluster.

In contrast to ingress traffic, where Kubernetes has the [Ingress]({{site.baseurl}}/about/about-kubernetes-ingress)
resource type to help manage the traffic, there is no Kubernetes Egress resource. Instead, how the egress traffic is
handled at a networking level is determined by the Kubernetes network implementation / CNI plugin being used by the
cluster. In addition, if a service mesh is being used, this can add egress behaviors on top of those the
network implementation provides.

There are three areas of behavior worth understanding for egress traffic, so you can choose a networking and/or service
mesh setup that best suits your needs:
- Restricting egress traffic
- Outgoing NAT behavior
- Egress gateways

### Restricting egress traffic

It's a common security requirement and best practice to restrict outgoing connections from the cluster. This is normally
achieved using [Network Policy]({{site.baseurl}}/about/about-network-policy) to define egress rules for each
microservice, often in conjunction with a [default deny]({{site.baseurl}}/about/about-network-policy#default-deny)
policy that ensures outgoing connections are denied by default, until a policy is defined to explicitly allow specific
traffic.

One limitation when using Kubernetes Network Policy to restrict access to specific external resources, is that the external
resources need to be specified as IP addresses (or IP address ranges) within the policy rules. If the IP addresses
associated with an external resource change, then every policy that referenced those IP addresses needs to be updated with
the new IP addresses. This limitation can be circumvented using Calico [Network
Sets]({{site.baseurl}}/security/external-ips-policy), or Calico Enterprise's support for [domain
names]({{site.baseurl}}/security/calico-enterprise/egress-access-controls) in policy rules.

In addition to using network policy, service meshes typically allow you to configure which external services each pod
can access. In the case of Istio, {{site.prodname}} can be integrated to enforce network policy at the service mesh
layer, including [L5-7 rules]({{site.baseurl}}/security/http-methods), as another alternative to using IP addresses in rules. To
learn more about the benefits of this kind of approach, read our [Adopt a zero trust network model for security
]({{site.baseurl}}/security/adopt-zero-trust) guide.

Note in addition to everything mentioned so far, perimeter firewalls can also be used to restrict outgoing connections,
for example to allow connections only to particular external IP address ranges, or external services. However, since
perimeter firewalls typically cannot distinguish individual pods, the rules apply equally to all pods in the cluster.
This provides some defense in depth, but cannot replace the requirement for network policy.

### NAT outgoing

Network Address Translation ({% include open-new-window.html text='NAT'
url='https://en.wikipedia.org/wiki/Network_address_translation' %}) is the process of mapping an IP address in a packet
to a different IP address as the packet passes through the device performing the NAT. Depending on the use case, NAT can
apply to the source or destination IP address, or to both addresses.

In the context of Kubernetes egress, NAT is used to allow pods to connect to services outside of the cluster if the pods
have IP addresses that are not routable outside of the cluster (for example, if the pod network is an overlay).

For example, if a pod in an overlay network attempts to connect to an IP address outside of the cluster, then the
node hosting the pod uses SNAT (Source Network Address Translation) to map the non-routable source IP address of the
packet to the node's IP address before forwarding on the packet.  The node then maps response packets coming in the
opposite direction back to the original pod IP address, so packets flow end-to-end in both directions, with neither
pod or external service being aware the mapping is happening.

In most clusters this NAT behavior is configured statically across the whole of the cluster. When using
{{site.prodname}}, the NAT behavior can be configured at a more granular level for particular address ranges using [IP
pools]({{site.baseurl}}/reference/resources/ippool). This effectively allows the scope of "non-routable" to be more
tightly defined than just "inside the cluster vs outside the cluster", which can be useful in some enterprise deployment
scenarios.

### Egress gateways

Another approach to Kubernetes egress is to route all outbound connections via one or more egress gateways. The gateways
SNAT (Source Network Address Translation) the connections so the external service being connected to sees the connection
as coming from the egress gateway. The main use case is to improve security, either with the egress gateway performing a
direct security role in terms of what connections it allows, or in conjunction with perimeter firewalls (or other
external entities). For example, so that perimeter firewalls see the connections coming from well known IP
addresses (the egress gateways) rather than from dynamic pod IP addresses they don't understand.

Egress gateways are not a native concept in Kubernetes itself, but are implemented by some Kubernetes network
implementations and some service meshes. For example, Calico Enterprise provides egress gateway functionality, plus the
ability to map namespaces (or even individual pods) to specific egress gateways. Perimeter firewalls (or other external
security entities) can then effectively provide per namespace security controls, even though they do not have visibility
to dynamic pod IP addresses.

As an alternative approach to egress gateways, {{site.prodname}} allows you to control pod IP address ranges based on
namespace, or node, or even at the individual pod level. Assuming no outgoing NAT is required, this provides a very
simple way for perimeter firewalls (or other external security entities) to integrate with Kubernetes for both ingress
and egress traffic. (Note that this approach relies on having enough address space available to sensibly assign IP
address ranges, for example to each namespace, so it can lead to IP address range exhaustion challenges for large scale
deployments. In these scenarios, using egress gateways is likely to be a better option.)

### Above and beyond

- [Adopt a zero trust network model for security]({{site.baseurl}}/security/adopt-zero-trust)
- [Use external IPs or networks rules in policy]({{site.baseurl}}/security/external-ips-policy)
- [Enforce network policy using Istio]({{site.baseurl}}/security/app-layer-policy)
- [Use HTTP methods and paths in policy rules]({{site.baseurl}}/security/http-methods)
- [Restrict a pod to use an IP address in a specific range]({{site.baseurl}}/networking/legacy-firewalls)
- [Assign IP addresses based on topology]({{site.baseurl}}/networking/assign-ip-addresses-topology)
- {% include enterprise_icon.html %}[Advanced egress access controls]({{site.baseurl}}/security/calico-enterprise/egress-access-controls)
