---
title: About Kubernetes Ingress
description: Learn about Kubernetes Ingress!
---

> <span class="glyphicon glyphicon-info-sign"></span> This guide provides optional background education, including
> education that is not specific to {{site.prodname}}.
{: .alert .alert-info}

In this guide you will learn:
- What is Kubernetes Ingress?
- Why use ingress?
- What are the differences between different ingress implementations?
- How does ingress and network policy interact?
- How does ingress and services fit together under the covers?

### What is Kubernetes Ingress?

Kubernetes Ingress builds on top of Kubernetes [Services]({{site.baseurl}}/about/about-kubernetes-services) to provide
load balancing at the application layer, mapping HTTP and HTTPS requests with particular domains or URLs to Kubernetes
services. Ingress can also be used to terminate SSL / TLS before load balancing to the service.

The details of how Ingress is implemented depend on which {% include open-new-window.html text='Ingress Controller'
url='https://kubernetes.io/docs/concepts/services-networking/ingress-controllers/' %} you are using. The Ingress
Controller is responsible for monitoring Kubernetes {% include open-new-window.html text='Ingress'
url='https://kubernetes.io/docs/concepts/services-networking/ingress/' %} resources and provisioning / configuring one
or more ingress load balancers to implement the desired load balancing behavior.

Unlike Kubernetes services, which are handled at the network layer (L3-4), ingress load balancers operate at the
application layer (L5-7). Incoming connections are terminated at the load balancer so it can inspect the individual HTTP /
HTTPS requests. The requests are then forwarded via separate connections from the load balancer to the chosen service
backing pods. As a result, network policy applied to the backing pods can restrict access to only allow connections from the load
balancer, but cannot restrict access to specific original clients.

### Why use Kubernetes Ingress?

Given that Kubernetes [Services]({{site.baseurl}}/about/about-kubernetes-services) already provide a mechanism for load
balancing access to services from outside of the cluster, why might you want to use Kubernetes Ingress?

The mainline use case is if you have multiple HTTP / HTTPS services that you want to expose through a single external IP
address, perhaps with each service having a different URL path, or perhaps as multiple different domains. This is lot
simpler from a client configuration point of view than exposing each service outside of the cluster using Kubernetes
Services, which would give each service a separate external IP address.

If on the other hand, your application architecture is fronted by a single "front end" microservice then Kubernetes
Services likely already meet your needs. In this case you might prefer to not add Ingress to the picture, both from a
simplicity point of view, and potentially also so you can more easily restrict access to specific clients using network
policy. In effect, your "front end" microservice already plays the role of Kubernetes Ingress, in a way that is not that
dissimilar to [in-cluster ingress](#in-cluster-ingress-solutions) solutions discussed below.

### Types of Ingress solutions

Broadly speaking there are two types of ingress solutions:
- In-cluster ingress - where ingress load balancing is performed by pods within the cluster itself.
- External ingress - where ingress load balancing is implemented outside of the cluster by
  appliances or cloud provider capabilities.

#### In-cluster ingress solutions

In-cluster ingress solutions use software load balancers running in pods within the cluster itself. There are many
different ingress controllers to consider that follow this pattern, including for example the NGINX ingress controller.

The advantages of this approach are that you can: 
- horizontally scale your ingress solution up to the limits of Kubernetes
- choose the ingress controller that best suits your specific needs, for example, with particular load balancing
  algorithms, or security options.

To get your ingress traffic to the in-cluster ingress pods, the ingress pods are normally exposed externally as a
Kubernetes service, so you can use any of the standard ways of accessing the service from outside of the cluster. A
common approach is use an external network load balancer or service IP advertisement, with `externalTrafficPolicy:local`.
This minimizes the number of network hops, and retains the client source IP address, which allows network policy to be used
to restrict access to the ingress pods to particular clients if desired.

![In-cluster ingress]({{site.baseurl}}/images/ingress-in-cluster.svg)

#### External ingress solutions

External ingress solutions use application load balancers outside of the cluster. The exact details and
features depend on which ingress controller you are using, but most cloud providers include an ingress controller that
automates the provisioning and management of the cloud provider's application load balancers to provide ingress.

The advantages of this type of ingress solution is that your cloud provider handles the operational complexity of the
ingress for you.  The downsides are a potentially more limited set of features compared to the rich range of in-cluster
ingress solutions, and the maximum number of services exposed by ingress being constrained by cloud provider specific
limits.

![External ingress]({{site.baseurl}}/images/ingres-external.svg)

Note that most application load balancers support a basic mode of operation of forwarding traffic to the chosen service
backing pods via the [node port]({{site.baseurl}}/about/about-kubernetes-services#node-port-services) of the
corresponding service.

In addition to this basic approach of load balancing to service node ports, some cloud providers support a second mode
of application layer load balancing, which load balances directly to the pods backing each service, without going via
node-ports or other kube-proxy service handling. This has the advantage of eliminating the potential second network hop
associated with node ports load balancing to a pod on a different node. The potential disadvantage is that if you are
operating at very high scales, for example with hundreds of pods backing a service, you may exceed the application layer
load balancers maximum limit of IPs it can load balance to in this mode. In this case switching to an in-cluster ingress
solution is likely the better fit for you.

### Show me everything!

All the above diagrams focus on connection level (L5-7) representation of ingress and services. You can learn more about
the network level (L3-4) interactions involved in handling the connections, including which scenarios client source IP
addresses are maintained, in the [About Kubernetes Services]({{site.baseurl}}/about/about-kubernetes-services) guide.

If you are already up to speed on how services work under the covers, here are some more complete diagrams that show details of how services are load balanced at the network layer (L3-4).

> Note: you can successfully use ingress without needing to understand this next level of detail! So feel free to skip
> over these diagrams if you don't want to dig deeper into how services and ingress interact under the covers.

**In-cluster ingress solution exposed as service type `LoadBalancer` with `externalTrafficPolicy:local`**

![In-cluster ingress with NLB local]({{site.baseurl}}/images/ingress-in-cluster-nlb-local.svg)

**External ingress solution via node ports**

![External ingress via node port]({{site.baseurl}}/images/ingress-external-node-ports.svg)

**External ingress solution direct to pods**

![External ingress direct to pods]({{site.baseurl}}/images/ingress-external-direct-to-pods.svg)

### Above and beyond

- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes Ingress networking   '
  url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-ingress-networking/' %}
- {% include open-new-window.html text='Video: Everything you need to know about Kubernetes Services networking   '
  url='https://www.projectcalico.org/everything-you-need-to-know-about-kubernetes-services-networking/' %}
