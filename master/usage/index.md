---
title: Using Calico
---

This section assumes you have some familiarity with Calico and have at
least read through
[Getting Started]({{site.baseurl}}/{{page.version}}/getting-started)
for an orchestrator.  The information here will hopefully provide direction
on achieving some common tasks and possibly some not so common tasks.

### calico/node

#### Configuring calico/node

The calico/node container is the main component in a Calico setup and as such
there are many aspects of it that can/need to be configured.

- When running calico/node on a host with multiple IP Addresses or interfaces
  the correct one must be selected, see 
  [Configuring a Node's IP Address and Subnet]({{site.baseurl}}/{{page.version}}/usage/configuration/node)
  to set or change the IP Address or method used to select it.
- When running Calico in a Kubernetes cluster is is possible to use
  the Kubernetes datastore, see
  [Configuring to use the Kubernetes Datastore Driver]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/#configuration-details)
  for configuring calico/node in that situation.
- For a full reference of all flags used, refer to the
  [Configuring calico/node]({{site.baseurl}}/{{page.version}}/reference/node/configuration)
  reference or the 
  [Configuring Felix]({{site.baseurl}}/{{page.version}}/reference/felix/configuration)
  reference.

#### Running calico/node

Here are a few options of how calico/node can be ran.  Depending on how you
are installing Calico this section may not be applicable to you as installation
and running of calico/node could be handled for you already.

- If using Kuberenetes, calico/node can be launched from a manifest, see
  [Calico Kubernetes Hosted Install]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted).
- Some Calico installation options may handle installing and running
  calico/node but some deployments will want to do this manually, the page
  [Running Calico Node Container as a Service]({{site.baseurl}}/{{page.version}}/usage/configuration/as-service)
  helps in those cases.
- Another way to launch calico node is to use the
  [`calicoctl node run` command]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/run)
  though it is not suggested for production deployments.

#### Decommissioning calico/node hosts

The calico/node container places information into the shared datastore
and additional information is attached during operations.  When removing hosts
it is neccessary to 
[Decomission a node]({{site.baseurl}}/{{page.version}}/usage/dcommissioning-a-node)
to clean up this information.
Decommissioning a node is also necessary when replacing hosts if the name
of your Calico node changes (i.e. the hostname changes).

### Using calicoctl

Before using
[calicoctl, it must be configured]({{site.baseurl}}/{{page.version}}/usage/calicoctl/install-and-configuration)
to access the datastore being used in your cluster be it
[etcdv2]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/etcdv2) or
[Kubernetes Datastore Driver]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/kubernetes).

An alternative to the calicoctl binary is the container calico/ctl that is
made available for each release, for more information see
[calico/ctl container]({{site.baseurl}}/{{page.version}}/usage/calicoctl/install-and-configuration).

{% comment %}
Everything in this comment area is referencing reference info and getting-started info.
I kind of like the info but since it isn't highlighting any Usage pages I don't know 
if it should be here.
### Restricting and allowing workload traffic

- Restricting traffic to workloads can be achieved by defining or modifying
  [policies (preferred)]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy)
  or [profiles]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile).
  Also if using Kubernetes is is recommended to use 
  [NetworkPolicy]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/tutorials/simple-policy#allow-access-using-a-networkpolicy)
  though currently only ingress policies are supported
  (Kubernetes is working on supporting egress).

- To secure the hosts running your pods, or any host, 
  [host endpoints]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/bare-metal#creating-host-endpoint-objects)
  can be created for any host running calico/node and then
  [Calico can be used to Secure Host Interfaces]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/bare-metal).

- Restricting access to a known remote host can be achived by creating a
  [host endpoint]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/bare-metal#creating-host-endpoint-objects)
  with the remote host's IP Address and using the labels assigned to the
  host endpoint in
  [policies]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy).
{% endcomment %}

### Configuring workload connectivity

Calico clusters are great themselves but if they did not allow incoming or
outgoing traffic their usage would be limited, due to that fact the following
tasks are useful.

- Enabling [Outbound connectivity]({{site.baseurl}}/{{page.version}}/usage/external-connectivity#outbound-connectivity)
  for workloads is handled by enabling NAT on
  [IP Pool]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool)
  configuration.
- [Inbound connectivity]({{site.baseurl}}/{{page.version}}/usage/external-connectivity#inbound-connectivity)
  can be handled through orchestrator supported options or by 
  [Configuring BGP Peering]({{site.baseurl}}/{{page.version}}/usage/configuration/bgp)
  to allow external hosts to directly access workloads.

### Enabling Calico traffic in the cloud

On some cloud providers it is necessary to
[Configure IP-in-IP]({{site.baseurl}}/{{page.version}}/usage/configuration/ip-in-ip)
on the
[IP Pools]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool)
used to ensure traffic between hosts is not dropped by the networking fabric.

### Utilizing route reflectors as cluster size increases

BIRD and BGP scales well but when cluster sizes approach 100 nodes the
processing becomes noticable and can be offset by setting up route reflectors.
Information about running route reflectors can be found on
[Configuring Bird as a Route Reflector]({{site.baseurl}}/{{page.version}}/usage/routereflector/bird-rr-config)
and 
[Calico BIRD Route Reflector container]({{site.baseurl}}/{{page.version}}/usage/routereflector/calico-routereflector)
with the details on configuring 
[BGP Peers here]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/bgppeer).

