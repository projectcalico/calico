---
title: Apply on forwarded traffic
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/getting-started/bare-metal/policy/forwarded'
---

If `applyOnForward` is `false`, the host endpoint policy applies to traffic to/from
 local processes only. 

If `applyOnForward` is `true`, the host endpoint policy applies to forwarded traffic:
- Incoming traffic from a host endpoint to a local workload (container/pod/VM).
- Outgoing traffic from a local workload to a host endpoint.
- Traffic from one host endpoint that is forwarded to another host endpoint.

By default, `applyOnForward` is `false`. 

Untracked policies and pre-DNAT policies must have `applyOnForward` set to `true`
because they apply to all forwarded traffic.

Forwarded traffic is allowed by default. In other words, if a host endpoint is
configured, but there are no rules that explicitly allow or deny a particular
forwarding flow (in any of policies with `applyOnForward` set to `true` that apply
to that host endpoint), that flow is still allowed. This is different from how {{site.prodname}}
treats traffic to or from a local process: traffic to or from a local process is
denied by default, if a host endpoint is configured but there is no applicable
policy that explicitly allows that traffic.

> **Note**: {{site.prodname}}'s handling of host endpoint policy has changed, since before
> Calico v2.7.0, in two ways:
> - It will not apply at all to forwarded traffic, by default. If you have an existing
> policy and you want it to apply to forwarded traffic, you need to add `applyOnForward: true` to the policy.
> - Even with `applyOnForward: true`, the treatment is not quite the same in
> Calico v2.7.0 as in previous releases, because–once a host endpoint is configured–
> Calico v2.7.0 allows forwarded traffic through that endpoint by default, whereas
> previous releases denied forwarded traffic through that endpoint by default.
> If you want to maintain the default-deny behavior for all host-endpoint forwarded
> traffic, you can create an empty policy with `applyOnForward` set to `true`
> that applies to all traffic on all host endpoints.
{: .alert .alert-info}
```
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
> [policy spec]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy#spec) for
> more discussion.
{: .alert .alert-info}

