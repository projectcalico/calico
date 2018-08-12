---
title: Security Policy Model
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v1.6/reference/security-model'
---

Calico applies security policy to **endpoints**. Calico policy is
defined in terms of **security profiles**, which contain lists of
**rules** to apply as well as sets of **tags**.

## Endpoints

Endpoints are the TAPs, veths or other interfaces, which are attached to
virtual machines or containers.

Calico applies one or more security profiles to each endpoint.

Calico always tries to fail safe: if the configuration for an endpoint
is missing, or no profiles are configured, Calico will drop traffic
to/from that endpoint. There is always an implicit default deny rule at
the end of the list of profiles.

## Security profiles: rules

Endpoints are configured to belong to one or more security profiles.
Profiles encode the policy (i.e. which packets to allow or deny) to
apply to an endpoint.

Policy is encoded as two lists of rules:

-   an **inbound** list, which is traversed for packets that are going
    *to* the endpoint
-   an **outbound** list, for packets coming *from* the endpoint

In the lists, each rule consists of a set of match criteria and an
action. The match criteria include:

-   protocol,
-   source/dest CIDR,
-   source/dest tag (see below),
-   source/dest port,
-   ICMP type and code.

Calico supports actions, "allow" and "deny", which immediately accept or
reject the packet. Once a packet is accepted or rejected further rules
are not processed.

If a packet does not match any of the rules in any of the profiles
attached to an endpoint then the default is to deny traffic.

If a workload (such as a virtual machine) has multiple endpoints (for
example, multiple vNICs) then each of those endpoints may belong to a
different set of security profiles.

## Security profiles: tags

Each profile also has a set of (opaque) tags attached to it. An endpoint
is considered a **member** of a tag if one of its profiles contains that
tag.

Profile rules may reference tags in the source and destination match
criteria. Calico calculates the tag memberships dynamically, updating
them as endpoints come and go and as profiles are updated. This allows
for very fine-grained but also maintainable policy.

For example, an operator could add the "db-user" tag to all endpoints
that are to use the database. Then, they can use a single "allow" rule
in the database's inbound chain to allow connections from all current
members of the "db-user" tag.

## Differences from OpenStack

Calico represents OpenStack security groups as profiles (with a single
tag containing the name of the security group). While this is a simple
1-to-1 mapping at the rule level, there are some differences between
Calico and OpenStack's security models to consider:

Effective security in OpenStack is a product of the interaction between
three kinds of objects: networks, routers and security groups. Calico,
on the other hand, **only** uses security groups for security
configuration; and networks and routers have no impact. The following
subsections go into this in more detail, and discuss how these concepts
map onto the Calico data model.

### Networks and Routers

As discussed [here]({{site.baseurl}}/{{page.version}}/getting-started/openstack/connectivity), networks and routers are not used
in Calico for connectivity purposes. Similarly, they serve no security
purpose in a Calico environment.

Calico can provide equivalent functionality to networks and routers
using security groups. To achieve it, rather than placing all ports that
need to communicate into a single network, place them all in a security
group that allows ingress from and egress to the same security group.

## Architecture

At present, the flow of security information proceeds as follows:

    [Configuration in OpenStack or other orchestrator] -(Plugin)-> [etcd] -(Felix)-> [Programmed iptables rules]

When a security group is configured, the Calico orchestrator plugin
discovers the new configuration. This configuration is translated into
the Calico data model and written to etcd. The Felix agent watches etcd
for changes and applies the policy using the kernel's iptables and
ipsets.
