---
title: About Network Policy
description: Learn about network policy!
---

> <span class="glyphicon glyphicon-info-sign"></span> This guide provides optional background education, including
> education that is not specific to {{site.prodname}}.
{: .alert .alert-info}

Kubernetes and {{site.prodname}} provide network policy APIs to help you secure your workloads.

In this guide you will learn:
- What network policy is and why it is important.
- The differences between Kubernetes and Calico network policies and when you might want to use each.
- Some best practices for using network policy.

### What is network policy?

Network policy is the primary tool for securing a Kubernetes network. It allows you to easily restrict the network
traffic in your cluster so only the traffic that you want to flow is allowed.

To understand the significance of network policy, let's briefly explore how network security was typically achieved
prior to network policy. Historically in enterprise networks, network security was provided by designing a physical
topology of network devices (switches, routers, firewalls) and their associated configuration. The physical topology
defined the security boundaries of the network. In the first phase of virtualization, the same network and network
device constructs were virtualized in the cloud, and the same techniques for creating specific network topologies of
(virtual) network devices were used to provide network security. Adding new applications or services often required
additional network design to update the network topology and network device configuration to provide the desired
security.

In contrast, the [Kubernetes network model]({{site.baseurl}}/about/about-k8s-networking) defines a "flat"
network in which every pod can communicate with all other pods in the cluster using pod IP addresses. This approach
massively simplifies network design and allows new workloads to be scheduled dynamically anywhere in the cluster with no
dependencies on the network design.

In this model, rather than network security being defined by network topology boundaries, it is defined using network
policies that are independent of the network topology. Network policies are further abstracted from the network by using
label selectors as their primary mechanism for defining which workloads can talk to which workloads, rather than IP
addresses or IP address ranges.

### Why is network policy important?

In an age where attackers are becoming more and more sophisticated, network security as a line of defense is more important
than ever.

While you can (and should) use firewalls to restrict traffic at the perimeters of your network (commonly referred to as
north-south traffic), their ability to police Kubernetes traffic is often limited to a granularity of the cluster as a
whole, rather than to specific groups of pods, due to the dynamic nature of pod scheduling and pod IP addresses. In
addition, the goal of most attackers once they gain a small foothold inside the perimeter is to move laterally (commonly
referred to as east-west) to gain access to higher value targets, which perimeter based firewalls can't police against.

Network policy on the other hand is designed for the dynamic nature of Kubernetes by following the standard Kubernetes
paradigm of using label selectors to define groups of pods, rather than IP addresses. And because network policy is
enforced within the cluster itself it can police both north-south and east-west traffic.

Network policy represents an important evolution of network security, not just because it handles the dynamic nature of
modern microservices, but because it empowers dev and devops engineers to easily define network security themselves,
rather than needing to learn low-level networking details or raise tickets with a separate team responsible for managing
firewalls. Network policy makes it easy to define intent, such as "only this microservice gets to connect to the
database", write that intent as code (typically in YAML files), and integrate authoring of network policies into git
workflows and CI/CD processes.

> Note: Calico and Calico Enterprise offer capabilities that can help perimeter firewalls integrate
> more tightly with Kubernetes. However, this does not remove the need or value of network policies within the cluster itself.)
{: .alert .alert-info }

### Kubernetes network policy

Kubernetes network policies are defined using the Kubernetes {% include open-new-window.html text='NetworkPolicy'
url='https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.21/#networkpolicy-v1-networking-k8s-io' %} resource.

The main features of Kubernetes network policies are:
- Policies are namespace scoped (i.e. you create them within the context of a specific namespace just like, for example, pods)
- Policies are applied to pods using label selectors
- Policy rules can specify the traffic that is allowed to/from other pods, namespaces, or CIDRs
- Policy rules can specify protocols (TCP, UDP, SCTP), named ports or port numbers

Kubernetes itself does not enforce network policies, and instead delegates their enforcement to network plugins. Most
network plugins implement the mainline elements of Kubernetes network policies, though not all implement every feature
of the specification.  (Calico does implement every feature, and was the original reference implementation of Kubernetes
network policies.)

To learn more about Kubernetes network policies, read the [Get started with Kubernetes network
policy]({{site.baseurl}}/security/kubernetes-network-policy) guide.

### Calico network policy

In addition to enforcing Kubernetes network policy, {{site.prodname}} supports its own
namespaced [NetworkPolicy]({{site.baseurl}}/reference/resources/networkpolicy) and non-namespaced
[GlobalNetworkPolicy]({{site.baseurl}}/reference/resources/globalnetworkpolicy) resources, which provide additional
features beyond those supported by Kubernetes network policy. This includes support for:
- policy ordering/priority
- deny and log actions in rules
- more flexible match criteria for applying policies and in policy rules, including matching on Kubernetes
  ServiceAccounts, and (if using Istio & Envoy) cryptographic identity and layer 5-7 match criteria such as HTTP & gRPC URLs.
- ability to reference non-Kubernetes workloads in polices, including matching on
  [NetworkSets]({{site.baseurl}}/reference/resources/networkset) in policy rules

While Kubernetes network policy applies only to pods, Calico network policy can be applied to multiple types of
endpoints including pods, VMs, and host interfaces.

To learn more about Calico network policies, read the [Get started with Calico network
policy]({{site.baseurl}}/security/calico-network-policy) guide.

### Benefits of using {{site.prodname}} for network policy

#### Full Kubernetes network policy support
Unlike some other network policy implementations, Calico implements the full set of Kubernetes network policy features.

#### Richer network policy
Calico network policies allow even richer traffic control than Kubernetes network policies if you need it. In addition,
Calico network policies allow you to create policy that applies across multiple namespaces using GlobalNetworkPolicy
resources.

#### Mix Kubernetes and Calico network policy
Kubernetes and Calico network policies can be mixed together seamlessly. One common use case for this is to split
responsibilities between security / cluster ops teams and developer / service teams. For example, giving the security /
cluster ops team RBAC permissions to define Calico policies, and giving developer / service teams RBAC permissions to
define Kubernetes network policies in their specific namespaces. As Calico policy rules can be ordered to be enforced
either before or after Kubernetes network policies, and can include actions such as deny and log, this allows the
security / cluster ops team to define basic higher-level more-general purpose rules, while empowering the developer /
service teams to define their own fine-grained constraints on the apps and services they are responsible for.

For more flexible control and delegation of responsibilities between two or more teams, Calico Enterprise extends this
model to provide [hierarchical policy](#hierarchical-policy).

![Example mix of network policy types]({{site.baseurl}}/images/example-k8s-calico-policy-mix.svg)

#### Ability to protect hosts and VMs
As {{site.prodname}} policies can be enforce on host interfaces, you can use them to protect your Kubernetes nodes (not
just your pods), including for example, limiting access to node ports from outside of the cluster. To learn more, check
out the {{site.prodname}} [policy for hosts]({{site.baseurl}}/security/hosts) guides.

#### Integrates with Istio
When used with Istio service mesh, {{site.prodname}} policy engine enforces the same policy model at the host networking
layer and at the service mesh layer, protecting your infrastructure from compromised workloads and protecting your
workloads from compromised infrastructure. This also avoids the need for dual provisioning of security at the service
mesh and infrastructure layers, or having to learn different policy models for each layer.

#### Extendable with Calico Enterprise
Calico Enterprise adds even richer network policy capabilities, with the ability
to specify hierarchical policies, with each team have particular boundaries of trust, and FQDN / domain names in policy
rules for restricting access to specific external services.

### Best practices for network policies

#### Ingress and egress
At a minimum we recommend that every pod is protected by network policy ingress rules that restrict what is allowed
to connect to the pod and on which ports. The best practice is also to define network policy egress rules that restrict
the outgoing connections that are allowed by pods themselves. Ingress rules protect your pod from attacks outside of the
pod. Egress rules help protect everything outside of the pod if the pod gets compromised, reducing the attack surface to
make moving laterally (east-west) or to prevent an attacker from exfiltrating compromised data from your cluster (north-south).

#### Policy schemas
Due to the flexibility of network policy and labelling, there are often multiple different ways of labelling and writing
policies that can achieve the same particular goal. One of the most common approaches is to have a small number of
global policies that apply to all pods, and then a single pod specific policy that defines all the ingress and egress
rules that are particular to that pod.

For example:
```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: front-end
  namespace: staging
spec:
  podSelector:
    matchLabels:
      app: back-end
  ingress:
    - from:
      - podSelector:
          matchLabels:
            app: front-end
    ports:
    - protocol: TCP
      port: 443
  egress:
    - to:
      - podSelector:
          matchLabels:
            app: database
    ports:
    - protocol: TCP
      port: 27017
```

#### Default deny
One approach to ensuring these best practices are being followed is to define [default
deny]({{site.baseurl}}/security/kubernetes-default-deny) network policies. These ensure that if no other policy is
defined that explicitly allows traffic to/from a pod, then the traffic will be denied. As a result, anytime a team
deploys a new pod, they are forced to also define network policy for the pod. It can be useful to use a {{site.prodname}}
GlobalNetworkPolicy for this (rather than needing to define a policy every time a new namespace is created) and to
include some exceptions to the default deny (for example to allow pods to access DNS).

For example, you might use the following policy to default-deny all (non-system) pod traffic except for DNS queries to kube-dns/core-dns.
```yaml
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-app-policy
spec:
  namespaceSelector: has(projectcalico.org/name) && projectcalico.org/name not in {"kube-system", "calico-system", "calico-apiserver"}
  types:
  - Ingress
  - Egress
  egress:
    - action: Allow
      protocol: UDP
      destination:
        selector: k8s-app == "kube-dns"
        ports:
        - 53
```

#### Hierarchical policy

[Calico Enterprise](https://docs.tigera.io/v3.11/security/tiered-policy) supports hierarchical network policy using policy tiers. RBAC
for each tier can be defined to restrict who can interact with each tier. This can be used to delegate trust across
multiple teams.

![Example tiers]({{site.baseurl}}/images/example-tiers.svg)

