---
title: Using Calico
---

This section contains information on using Calico.

## Calico software components

There are several Calico components that may be ran as part of your
installation, check out the
[Getting Started]({{site.baseurl}}/{{page.version}}/getting-started)
section for the components that are needed for your specific orchestrator.
Here are the common components with links to relevant sections for configuring
and operating those components.

- [Calico node container]({{site.baseurl}}/{{page.version}}/reference/node/configuration)
  - [Felix]({{site.baseurl}}/{{page.version}}/reference/node/reference/felix/configuration)
  - [BGP]({{site.baseurl}}/{{page.version}}/usage/configuration/bgp)
  - [Running Calico Node Container as a Service]({{site.baseurl}}/{{page.version}}/usage/configuration/as-service)
  - [Configuring a Node IP Address and Subnet]({{site.baseurl}}/{{page.version}}/usage/configuration/node)

- [Calico policy controller]({{site.baseurl}}/{{page.version}}/reference/policy-controller/configuration)

- Orchestrator plugin
  - CNI
    - [Calico cni container]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted/)
  - Libnetwork
    - [Calico node container]({{site.baseurl}}/{{page.version}}/reference/node/configuration)
  - [OpenStack ML2]({{site.baseurl}}/{{page.version}}/usage/openstack/configuration#ml2-ml2_confini)

- calicoctl binary
  - [etcdv2]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/etcdv2)
  - [Kubernetes Datastore Driver]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/kubernetes)


## Concept areas

There are several concepts that Calico uses, below are
those concept areas and links to documentation applicable to their
configuration or operation.

- Datastore
  - Calico node container
    - [Node reference]({{site.baseurl}}/{{page.version}}/reference/node/configuration)
    - [Kubernetes Datastore Driver]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/#configuration-details)
  - CNI
    - [Calico cni container]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted/)
  - Libnetwork
    - [Calico node container]({{site.baseurl}}/{{page.version}}/reference/node/configuration)
  - calicoctl
    - [etcdv2]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/etcdv2)
    - [Kubernetes Datastore Driver]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/kubernetes)
- IP Pools
  - [Outbound connectivity]({{site.baseurl}}/{{page.version}}/usage/external-connectivity#outbound-connectivity)
  - [Configuring IP-in-IP]({{site.baseurl}}/{{page.version}}/usage/configuration/ip-in-ip)
  - [IP Pool reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool)
- Policy/Profile
  - [Policy reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy)
  - [Profile reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile)
- Host Endpoints
  - [Host protection]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/bare-metal)
- BGP
  - [Configuring BGP Peers]({{site.baseurl}}/{{page.version}}/usage/configuration/bgp)
  - [BGP Peer reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/bgppeer)
  - [Configuring Bird as a Route Reflector]({{site.baseurl}}/{{page.version}}/usage/routereflector/bird-rr-config)
  - [Calico BIRD Route Reflector container]({{site.baseurl}}/{{page.version}}/usage/routereflector/calico-routereflector)
  - [Inbound connectivity]({{site.baseurl}}/{{page.version}}/usage/external-connectivity#inbound-connectivity)
