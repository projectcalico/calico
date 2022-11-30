---
title: Creating policy for basic connectivity
description: Customize the Calico failsafe policy to protect host endpoints.
canonical_url: '/reference/host-endpoints/connectivity'
---

When a host endpoint is added, if there is no security policy for that
endpoint, {{site.prodname}} will default to denying traffic to/from that endpoint,
except for traffic that is allowed by the [failsafe rules](failsafe).

While the [failsafe rules](failsafe) provide protection against removing all
connectivity to a host:

-   They are overly broad in allowing inbound SSH on any interface and
    allowing traffic out to etcd's ports on any interface.
    
-   Depending on your network, they may not cover all the ports that are
    required; for example, your network may rely on allowing ICMP,
    or DHCP.

Therefore, we recommend creating a failsafe {{site.prodname}} security policy that
is tailored to your environment. The example command below shows one
example of how you might do that; the command uses `calicoctl` to create a single 
policy resource, which:

  - Applies to all known endpoints.
  - Allows inbound ssh access from a defined "management" subnet.
  - Allows outbound connectivity to etcd on a particular IP; if
    you have multiple etcd servers you should duplicate the rule
    for each destination.
  - Allows inbound ICMP.
  - Allows outbound UDP on port 67, for DHCP.

When running this command, replace the placeholders in angle brackets with
appropriate values for your deployment.
<!-- -->

```bash
cat <<EOF | calicoctl create -f -
- apiVersion: projectcalico.org/v3
  kind: GlobalNetworkPolicy
  metadata:
    name: failsafe
  spec:
    selector: "all()"
    order: 0
    ingress:
    - action: Allow
      protocol: TCP
      source:
        nets:
        - "<your management CIDR>"
      destination:
        ports: [22]
    - action: Allow
      protocol: ICMP
    egress:
    - action: Allow
      protocol: TCP
      destination:
        nets:
        - "<your etcd IP>/32"
        ports: [<your etcd ports>]
    - action: Allow
      protocol: UDP
      destination:
        ports: [67]
EOF
```

Once you have such a policy in place, you may want to disable the
[failsafe rules](failsafe).

> **Note**: Packets that reach the end of the list of rules fall-through to the 
> next policy (sorted by the `order` field).
>
> The selector in the policy, `all()`, will match *all* endpoints,
> including any workload endpoints. If you have workload endpoints as
> well as host endpoints then you may wish to use a more restrictive
> selector. For example, you could label management interfaces with
> label `endpoint_type = management` and then use selector
> `endpoint_type == "management"`
>
> If you are using {{site.prodname}} for networking workloads, you should add
> inbound and outbound rules to allow BGP:  add an ingress and egress rule
> to allow TCP traffic to destination port 179.
{: .alert .alert-info}

