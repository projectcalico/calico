---
title: Apply on forwarded traffic
description: Learn the subtleties using the applyOnForward option in host endpoint policies.
canonical_url: '/reference/host-endpoints/forwarded'
---

If `applyOnForward` is `false`, the host endpoint policy applies to traffic to/from
 local processes only. 

If `applyOnForward` is `true`, the host endpoint policy also applies to forwarded traffic:
- Traffic that comes in via a host endpoint and is forwarded to a local workload (container/pod/VM).
- Traffic from a local workload that is forwarded out via a host endpoint.
- Traffic that comes in via a host endpoint and is forwarded out via another host endpoint.

By default, `applyOnForward` is `false`. 

Untracked policies and pre-DNAT policies must have `applyOnForward` set to `true`
because they apply to all forwarded traffic.

Forwarded traffic is allowed by default if no policies apply to the endpoint and direction. In
other words, if a host endpoint is configured, but there are no policies with `applyOnForward`
set to `true` that apply to that host endpoint and traffic direction, forwarded traffic is 
allowed in that direction. For example if a forwarded flow is incoming via a host endpoint, but there are
no Ingress policies with `applyOnForward: true` that apply to that host endpoint, the flow is
allowed.  If there are `applyOnForward: true` policies that select the host endpoint and direction,
but no rules in the policies allow the traffic, the traffic is denied.

This is different from how {{site.prodname}} treats traffic to or from a local process:
if a host endpoint is configured and there are no policies that select the host endpoint in
the traffic direction, or no rules that allow the traffic, the traffic is denied.

Traffic that traverses a host endpoint and is forwarded to a workload endpoint must also pass
the applicable workload endpoint policy, if any. That is to say, if an `applyOnForward: true` host
endpoint policy allows the traffic, but workload endpoint policy denies it, the packet is still dropped.

Traffic that ingresses one host endpoint, is forwarded, and egresses host endpoint must
pass ingress policy on the first host endpoint and egress policy on the second host endpoint.

> **Note**: {{site.prodname}}'s handling of host endpoint policy has changed, since before
> Calico v3.0, in two ways:
> - It will not apply at all to forwarded traffic, by default. If you have an existing
> policy and you want it to apply to forwarded traffic, you need to add `applyOnForward: true` to the policy.
> - Even with `applyOnForward: true`, the treatment is not quite the same in
> Calico v3.0 as in previous releases, because–once a host endpoint is configured–
> Calico v3.0 allows forwarded traffic through that endpoint by default, whereas
> previous releases denied forwarded traffic through that endpoint by default.
> If you want to maintain the default-deny behavior for all host-endpoint forwarded
> traffic, you can create an empty policy with `applyOnForward` set to `true`
> that applies to all traffic on all host endpoints.
{: .alert .alert-info}
```bash
calicoctl apply -f - <<EOF
- apiVersion: projectcalico.org/v3
  kind: GlobalNetworkPolicy
  metadata:
    name: empty-default-deny
  spec:
    types: 
      - Ingress
      - Egress
    selector: has(host-endpoint)
    applyOnForward: true
EOF
```
> **Note**: This policy has no `order` field specified which causes it to default
> to the highest value. Because higher order values have the lowest order of precedence,
> {{site.prodname}} will apply this policy after all other policies. Refer to the 
> [policy spec]({{ site.baseurl }}/reference/resources/networkpolicy#spec) for
> more discussion.
{: .alert .alert-info}

