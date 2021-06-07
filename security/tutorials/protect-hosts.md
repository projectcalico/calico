---
title: Protect hosts tutorial
description: Learn how to secure incoming traffic from outside the cluster using Calico host endpoints with network policy, including allowing controlled access to specific Kubernetes services.
canonical_url: '/security/tutorials/protect-hosts'
---

Imagine that the administrator of a Kubernetes cluster wants to secure it as much as
possible against incoming traffic from outside the cluster.  But suppose that
the cluster provides various useful services that are exposed as Kubernetes
NodePorts, i.e., as well-known TCP port numbers that appear to be available on
any node in the cluster. The administrator does want to expose some
of those NodePorts to traffic from outside.

In this example we will use pre-DNAT policy applied to the external interfaces
of each cluster node:

- to disallow incoming traffic from outside, in general

- but then to allow incoming traffic to particular NodePorts.

We use pre-DNAT policy for these purposes, instead of normal host endpoint
policy, because:

1. We want the protection against general external traffic to apply regardless
   of where that traffic is destined for - for example, to a locally hosted
   pod, or to a pod on another node, or to a local server process running on
   the host itself.  Pre-DNAT policy is enforced in all of those cases - as we
   want - whereas normal host endpoint policy is not enforced for traffic going
   to a local pod.

2. We want to write this policy in terms of the advertised NodePorts, not in
   terms of whatever internal port numbers those may be transformed to.
   kube-proxy on the ingress node will use a DNAT to change a NodePort number
   and IP address to those of one of the pods that backs the relevant Service.
   Our policy therefore needs to take effect _before_ that DNAT - and that
   means that it must be a pre-DNAT policy.

> Note: This tutorial is intended to be used with named host endpoints, i.e. host endpoints with `interfaceName` set to a specific interface name.
> This tutorial does not work, as-is, with host endpoints with `interfaceName: "*"`.
{: .alert .alert-info }

Here is the pre-DNAT policy that we need to disallow incoming external traffic
in general:

```bash
calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-cluster-internal-ingress
spec:
  order: 10
  preDNAT: true
  applyOnForward: true
  ingress:
    - action: Allow
      source:
        nets: [10.240.0.0/16, 192.168.0.0/16]
  selector: has(host-endpoint)
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: drop-other-ingress
spec:
  order: 20
  preDNAT: true
  applyOnForward: true
  ingress:
    - action: Deny
  selector: has(host-endpoint) 
EOF
```

Specifically, this policy allows traffic coming from IP addresses that are
known to be cluster-internal, and denies traffic from any other sources.  For
the cluster-internal IP addresses in this example, we assume 10.240.0.0/16 for
the nodes' own IP addresses, and 192.168.0.0/16 for IP addresses that
Kubernetes will assign to pods; obviously you should adjust for the CIDRs that
are in use in your own cluster.

> **Note**: The `drop-other-ingress` policy has a higher `order` value than
> `allow-cluster-internal-ingress`, so that it applies _after_
> `allow-cluster-internal-ingress`.
>
> The explicit `drop-other-ingress` policy is needed because there is no
> automatic default-drop semantic for pre-DNAT policy. There _is_ a
> default-drop semantic for normal host endpoint policy but—as noted above—normal
> host endpoint policy is not always enforced.
{: .alert .alert-info}

We also need policy to allow _egress_ traffic through each node's external
interface.  Otherwise, when we define host endpoints for those interfaces, no
egress traffic will be allowed from local processes (except for traffic that is
allowed by the [failsafe rules]({{ site.baseurl }}/reference/host-endpoints/failsafe). Because there is no default-deny
rule for forwarded traffic, forwarded traffic will be allowed for host endpoints.

```bash
calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-outbound-external
spec:
  order: 10
  egress:
    - action: Allow
  selector: has(host-endpoint)
EOF
```

> **Note**: These egress rules are defined as normal host endpoint policies, not
> pre-DNAT, because pre-DNAT policy does not support egress rules. (Which is
> because pre-DNAT policies are enforced at a point in the Linux networking
> stack where it is not yet determined what a packet's outgoing interface will
> be.)
>
> Because these are normal host endpoint policies which do not
> apply to forwarded traffic (`applyOnForward` is `false`), they
> are not enforced for traffic that is sent from a local pod.
>
> The policy above allows applications or server processes running on the nodes
> themselves (as opposed to in pods) to connect outbound to any destination.
> In case you have a use case for restricting to particular IP addresses, you
> can achieve that by adding a corresponding `destination` spec.
{: .alert .alert-info}

Now we can define a host endpoint for the outwards-facing interface of each
node.  The policies above all have a selector that makes them applicable to any
endpoint with a `host-endpoint` label, so we should include that label in our
definitions.  For example, for `eth0` on `node1`:

```bash
calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: HostEndpoint
metadata:
  name: node1-eth0
  labels:
    host-endpoint: ingress
spec:
  interfaceName: eth0
  node: node1
EOF
```

After defining host endpoints for each node, you should find that internal
cluster communications are all still working as normal—for example, that you
can successfully execute commands like `calicoctl get hep` and `calicoctl get
pol`—but that it is impossible to connect into the cluster from outside
(except for any [failsafe rules]({{ site.baseurl }}/reference/host-endpoints/failsafe).  
For example, if the
cluster includes a Kubernetes Service that is exposed as NodePort 31852, you
should find, at this point, that that NodePort works from within the cluster,
but not from outside.

To open a pinhole for that NodePort, for external access, you can configure a
pre-DNAT policy like this:

```bash
calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-nodeport
spec:
  preDNAT: true
  applyOnForward: true
  order: 10
  ingress:
    - action: Allow
      protocol: TCP
      destination:
        selector: has(host-endpoint)
        ports: [31852]
  selector: has(host-endpoint)
EOF
```

If you wanted to make that NodePort accessible only through particular nodes, you could achieve that by giving those nodes a particular `host-endpoint` label:

```yaml
host-endpoint: <special-value>
```

and then using `host-endpoint=='<special-value>'` as the selector of the
`allow-nodeport` policy, instead of `has(host-endpoint)`.
