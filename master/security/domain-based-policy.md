---
title: Admin policy using domain names
canonical_url: 'https://docs.projectcalico.org/master/security/domain-based-policy'
---

In a Kubernetes deployment, the cluster administrator can configure
[GlobalNetworkPolicy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/globalnetworkpolicy)
to allow egress traffic from the cluster to peers that are identified
by their domain names.  {{site.prodname}} has long supported
identifying peers directly by IP, but it will usually be more
meaningful and resilient to identify a resource *outside* the
immediate Kubernetes cluster - such as a cloud-provider database like
AWS's RDS - by its domain name instead of its IP.

> **Note**: Similarly, in order to address endpoints and services
> *within* the cluster, we apply Kubernetes labels to convey their
> roles, and then select on those labels in Calico policy, rather than
> addressing those endpoints and services directly by IP.  So using
> domain names for external resources is somewhat analogous to using
> labels for internal ones.  Using domain names for services *within*
> the cluster is not supported by the feature described on this page,
> because Kubernetes labels can and should be used for those instead.
{: .alert .alert-info}

Specifically, a GlobalNetworkPolicy can have egress rules with
`action: Allow` and a `domains` field specifying the possible domain
names to which egress traffic is allowed.

> **Note**: This makes sense when egress traffic from the workloads
> concerned (i.e. that the policy applies to) is denied by default.
> In other words, so that the GlobalNetworkPolicy with domain names is
> poking holes in a generally closed wall around the cluster.
{: .alert .alert-info}

There are two ways for a rule to specify allowed domain names:

1.  By listing those domain names directly in `domains.names`.

2.  By creating a
    [GlobalDomainSet]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/globaldomainset)
    resource - which groups together a set of domain names that you
    want to label in the same way - and using `domains.selector` to
    select GlobalDomainSets by their labels.  The effect then is to
    allow egress to all of the domain names listed in all of the
    selected GlobalDomainSets.

### Understanding which domain names will work

On the wire, data packets have IP addresses, not domain names, and it
is important to understand that this kind of policy, using domain
names, will only work as intended when {{site.prodname}} can
unambiguously predict the IP address that a client workload will use
when connecting to that name.  Or can discover a set of possible IP
addresses, such that it is guaranteed that the client workload will
use one of those.  In either of those cases, {{site.prodname}} can
open pinholes for the possible IPs that map to the configured domain
name, and then traffic to that domain name will be allowed as
intended.

Specifically, this means that when {{site.prodname}} does a DNS lookup
for a domain name (from somewhere in the cluster), it has to get the
same IP as a connecting client workload would; or a set of IPs that
includes the one that a connecting client workload would get.

In practice that is likely to be true for resources that are close by,
like services associated with the local cloud infrastructure.  It is
much less reliable for global services like `google.com` that can map
to hundreds of IP addresses.  Hence this feature targets the former
services and not the latter.  If you configure policy with a domain
name for which {{site.prodname}} can't reliably predict the IP that a
client workload will use, it means that a connection to that domain
name may not be allowed.

> **Note**: {{site.prodname}}'s predictive abilities here are
> implementation-dependent and so likely to improve in future
> releases.
{: .alert .alert-info}
