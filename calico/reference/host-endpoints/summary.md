---
title: Summary
description: How different host endpoint rules affect packet flows. 
canonical_url: '/reference/host-endpoints/summary'
---

## When do host endpoint policies apply?

Normal host endpoint policies apply to traffic that arrives on
and/or is sent to a host interface, but the rules for applying untracked and
pre-DNAT policies differ in some cases. Here we present and summarize all of
those rules together, for all possible flows and all types of host endpoints 
policy.

For packets that arrive on a host interface and are destined for a local
workload, i.e., a locally-hosted pod, container or VM:

- Pre-DNAT policies apply.

- Normal policies do apply if `applyOnForward` is `true`. 
  Normal policies do not apply if `applyOnForward` is `false`.

- Untracked policies technically do apply, but never have any net positive
  effect for such flows.
  
  > **Note**: To be precise, untracked policy for the incoming host interface may
  > apply in the forwards direction, and if so it will have the effect of forwarding
  > the packet to the workload without any connection tracking. But then, in
  > the reverse direction, there will be no conntrack state for the return
  > packets to match, and there is no application of any egress rules that may
  > be defined by the untracked policy—so unless the workload's policy
  > specifically allows the relevant source IP, the return packet will be
  > dropped. That is the same overall result as if there was no untracked
  > policy at all, so in practice it is as if untracked policies do not apply
  > to this flow.
  {: .alert .alert-info}

For packets that arrive on a host interface and are destined for a local
server process in the host namespace:

- Untracked, pre-DNAT and normal policies all apply.

- If a packet is explicitly allowed by untracked policy, it skips over any
  pre-DNAT and normal policy.

- If a packet is explicitly allowed by pre-DNAT policy, it skips over any
  normal policy.

For packets that arrive on a host interface (A) and are forwarded out of the
same or another host interface (B):

- Untracked policies apply, for both host interfaces A and B, but only the
  ingress rules that are defined in those policies.  The forwards direction is
  governed by the ingress rules of untracked policies that apply to interface
  A, and the reverse direction is governed by the ingress rules of untracked
  policies that apply to interface B, so those rules should be defined
  symmetrically.

- Pre-DNAT policies apply, specifically the ingress rules of the pre-DNAT
  policies that apply to interface A.  (The reverse direction is allowed by
  conntrack state.)

- Normal policies apply if `applyOnForward` is `true`: specifically, the ingress
  rules of the normal policies that apply to interface A, and the egress rules of
  the normal policies that apply to interface B. (The reverse direction is
  allowed by conntrack state.) Normal policies do not apply if `applyOnForward`
  is `false`.

- If a packet is explicitly allowed by untracked policy, it skips over any
  pre-DNAT and normal policy.

- If a packet is explicitly allowed by pre-DNAT policy, it skips over any
  normal policy.

For packets that are sent from a local server process (in the host namespace)
out of a host interface:

- Untracked policies apply, specifically the egress rules of the untracked
  policies that apply to the host interface.

- Normal policies apply, specifically the egress rules of the normal policies
  that apply to that host interface.

- Pre-DNAT policies do not apply.

For packets that are sent from a local workload out of a host interface:

- No untracked or pre-DNAT host endpoint policies apply.

- Normal policies apply if `applyOnForward` is `true`: specifically, the egress 
  rules of the normal policies that apply to the outgoing interface. (The reverse
  direction is allowed by conntrack state.) Normal policies do not apply if 
  `applyOnForward` is `false`.

