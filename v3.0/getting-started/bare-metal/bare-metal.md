---
title: Using Calico to Secure Host Interfaces
canonical_url: 'https://docs.projectcalico.org/v3.7/getting-started/bare-metal/bare-metal'
---

This guide describes how to use {{site.prodname}} to secure the network interfaces
of the host itself (as opposed to those of any container/VM workloads
that are present on the host). We call such interfaces "host endpoints",
to distinguish them from "workload endpoints" (such as containers or VMs).

{{site.prodname}} supports the same rich security policy model for host endpoints (host
endpoint policy) that it supports for workload endpoints. Host endpoints can
have labels, and their labels are in the same "namespace" as those of workload
endpoints. This allows security rules for either type of endpoint to refer to
the other type (or a mix of the two) using labels and selectors.

{{site.prodname}} does not support setting IPs or policing MAC addresses for host
interfaces, it assumes that the interfaces are configured by the
underlying network fabric.

{{site.prodname}} distinguishes workload endpoints from host endpoints by a configurable
prefix.  Unless you happen to have host interfaces whose name matches the
default for that prefix (`cali`), you won't need to change it.  In case you do,
see the `InterfacePrefix` configuration value at [Configuring
Felix]({{site.baseurl}}/{{page.version}}/reference/felix/configuration).
Interfaces that start with a value listed in `InterfacePrefix` are assumed to
be workload interfaces.  Others are treated as host interfaces.

{{site.prodname}} blocks all traffic to/from workload interfaces by default;
allowing traffic only if the interface is known and policy is in place.
However, for host endpoints, {{site.prodname}} is more lenient; it only polices
traffic to/from interfaces that it's been explicitly told about. Traffic
to/from other interfaces is left alone.

You can use host endpoint policy to secure a NAT gateway or router. {{site.prodname}}
supports selector-based policy when running on a gateway or router, allowing for
rich, dynamic security policy based on the labels attached to your host endpoints.

You can apply host endpoint policies to three types of traffic:
- Traffic that is terminated locally.
- Traffic that is forwarded between host endpoints.
- Traffic that is forwarded between a host endpoint and a workload endpoint on the
same host.

Set the `applyOnForward` flag to `true` to apply a policy to forwarded traffic.
See [GlobalNetworkPolicy spec]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/globalnetworkpolicy#spec).

> **Note**: Both traffic forwarded between host endpoints and traffic forwarded
> between a host endpoint and a workload endpoint on the same host is regarded as
> `forwarded traffic`.
>
> ![]({{site.baseurl}}/images/bare-metal-packet-flows-AOF.png)
{: .alert .alert-info}

## Installation overview

To make use of {{site.prodname}}'s host endpoint support, you will need to complete
the following steps.


1.  [Create an etcd cluster, if you haven't already](#creating-an-etcd-cluster).
1.  [Install and configure `calicoctl`](#install-and-configure-calicoctl).
1.  [Install the Felix daemon on each host](#installing-felix).
1.  [Initialize the etcd database](#initializing-the-etcd-database).
1.  [Add policy to allow basic connectivity](#creating-basic-connectivity-and-policy).
1.  [Create host endpoint objects in etcd](#creating-host-endpoint-objects) for each interface you want
    {{site.prodname}} to police. (In a later
    release, we plan to support interface templates to remove the need to explicitly
    configure every interface).
1.  [Insert policy into etcd](#creating-more-security-policy) for {{site.prodname}} to apply.
1.  [Decide whether to disable "failsafe SSH/etcd" access](#failsafe-rules).


## Creating an etcd cluster

If you haven't already created an etcd cluster for your {{site.prodname}}
deployment, you'll need to create one.

To create a single-node etcd cluster for testing, download an etcd v3.x
release from [the etcd releases archive](https://github.com/coreos/etcd/releases); we recommend using
the most recent bugfix release. Then follow the instructions on that
page to unpack and run the etcd binary.

To create a production cluster, you should follow the guidance in the
[etcd manual](https://coreos.com/etcd/docs/latest/). In particular, the
[clustering guide](https://coreos.com/etcd/docs/latest/).

### Install and configure calicoctl

1. [Install calicoctl as a binary](/{{page.version}}/usage/calicoctl/install#installing-calicoctl-as-a-binary).

1. [Configure calicoctl to connect to etcd](/{{page.version}}/usage/calicoctl/configure/).

1. Return to this page and continue to the [next section](#installing-felix).

## Installing Felix

{% include ppa_repo_name %}

There are several ways to install Felix.

-   If you are running Ubuntu 14.04 or 16.04, you can install from our PPA:

        sudo add-apt-repository ppa:project-calico/{{ ppa_repo_name }}
        sudo apt-get update
        sudo apt-get upgrade
        sudo apt-get install calico-felix

-   If you are running a RedHat 7-derived distribution, you can install
    from our RPM repository:

        cat > /etc/yum.repos.d/calico.repo <<EOF
        [calico]
        name=Calico Repository
        baseurl=http://binaries.projectcalico.org/rpm/{{ ppa_repo_name }}/
        enabled=1
        skip_if_unavailable=0
        gpgcheck=1
        gpgkey=http://binaries.projectcalico.org/rpm/{{ ppa_repo_name }}/key
        priority=97
        EOF

        yum install calico-felix

-   If you are running another distribution, follow the instructions in
    [this document](bare-metal-install) to use the `calico-felix` binary
    directly.

-   If you want to run under Docker, you can use `calicoctl node run --node-image={{page.registry}}{{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}` to start
    the `{{site.nodecontainer}}` container image.  This container packages up the core {{site.prodname}}
    components to provide both {{site.prodname}} networking and network policy.  Running
    the container automatically pre-initializes the etcd database (which the
    other installations methods do not).  See the
    [`calicoctl node run`]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/run)
    guide for details.

Until you initialize the database, Felix will make a regular log that it
is in state "wait-for-ready". The default location for the log file is
`/var/log/calico/felix.log`.

## Initializing the etcd database

If you are using the container-based installation (using the `{{site.nodecontainer}}`
container image), the database is initialized as soon as you start the first
node instance.

If you are self-installed you should configure a `node` resource for each
host running Felix.  In this case, the database is initialized after
creating the first `node` resource.  For a deployment that does not include
the {{site.prodname}}/BGP integration, the specification of a node resource just requires
the name of the node;  for most deployments this will be the same as the
hostname.

```
cat << EOF | calicoctl create -f -
- apiVersion: projectcalico.org/v3
  kind: Node
  metadata:
    name: <node name or hostname>
EOF
```

If you check the Felix logfile after this step, the logs should
transition from periodic notifications that Felix is in state
"wait-for-ready" to a stream of initialization messages.

## Creating basic connectivity and policy

When a host endpoint is added, if there is no security policy for that
endpoint, {{site.prodname}} will default to denying traffic to/from that endpoint,
except for traffic that is allowed by the [failsafe rules](#failsafe-rules).

While the [failsafe rules](#failsafe-rules) provide protection against removing all
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

```
cat << EOF | calicoctl create -f -
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
[failsafe rules](#failsafe-rules).

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


## Creating host endpoint objects

For each host endpoint that you want {{site.prodname}} to secure, you'll need to
create a host endpoint object in etcd.  Use the `calicoctl create` command
to create a host endpoint resource (`HostEndpoint`).

There are two ways to specify the interface that a host endpoint should
refer to. You can either specify the name of the interface or its
expected IP address. In either case, you'll also need to know the name given to
the {{site.prodname}} node running on the host that owns the interface; in most cases this
will be the same as the hostname of the host.

For example, to secure the interface named `eth0` with IP 10.0.0.1 on
host `my-host`, run the command below.  The name of the endpoint is an
arbitrary name required for endpoint identification.

When running this command, replace the placeholders in angle brackets with
appropriate values for your deployment.

```
cat << EOF | calicoctl create -f -
- apiVersion: projectcalico.org/v3
  kind: HostEndpoint
  metadata:
    name: <name of endpoint>
    labels:
      role: webserver
      environment: production
  spec:
    interfaceName: eth0
    node: <node name or hostname>
    profiles: [<list of profile IDs>]
    expectedIPs: ["10.0.0.1"]
EOF
```

> **Note**: Felix tries to detect the correct hostname for a system. It logs
> out the value it has determined at start-of-day in the following
> format:
>
> `2015-10-20 17:42:09,813 \[INFO\]\[30149/5\] calico.felix.config 285: Parameter FelixHostname (Felix compute host hostname) has value 'my-hostname' read from None`
>
> The value (in this case `'my-hostname'`) needs to match the hostname
> used in etcd. Ideally, the host's system hostname should be set
> correctly but if that's not possible, the Felix value can be
> overridden with the FelixHostname configuration setting. See
> configuration for more details.
{: .alert .alert-info}

Where `<list of profile IDs>` is an optional list of security profiles
to apply to the endpoint and labels contains a set of arbitrary
key/value pairs that can be used in selector expressions.

<!-- TODO(smc) data-model: Link to new data model docs. -->

> **Important**: When rendering security rules on other hosts, {{site.prodname}} uses the
> `expectedIPs` field to resolve label selectors
> to IP addresses. If the `expectedIPs` field is omitted
> then security rules that use labels will fail to match
> this endpoint.
{: .alert .alert-danger}

Or, if you knew that the IP address should be 10.0.0.1, but not the name
of the interface:

```
cat << EOF | calicoctl create -f -
- apiVersion: projectcalico.org/v3
  kind: HostEndpoint
  metadata:
    name: <name of endpoint>
    labels:
      role: webserver
      environment: production
  spec:
    node: <node name or hostname>
    profiles: [<list of profile IDs>]
    expectedIPs: ["10.0.0.1"]
EOF
```

After you create host endpoint objects, Felix will start policing
traffic to/from that interface. If you have no policy or profiles in
place, then you should see traffic being dropped on the interface.

> **Note**: By default, {{site.prodname}} has a failsafe in place that whitelists certain
> traffic such as ssh. See below for more details on
> disabling/configuring the failsafe rules.
{: .alert .alert-info}

If you don't see traffic being dropped, check the hostname, IP address
and (if used) the interface name in the configuration. If there was
something wrong with the endpoint data, Felix will log a validation
error at `WARNING` level and it will ignore the endpoint:

    $ grep "Validation failed" /var/log/calico/felix.log
    2016-05-31 12:16:21,651 [WARNING][8657/3] calico.felix.fetcd 1017:
        Validation failed for host endpoint HostEndpointId<eth0>, treating as
        missing: 'name' or 'expected_ipvX_addrs' must be present.;
        '{ "labels": {"foo": "bar"}, "profile_ids": ["prof1"]}'

The error can be quite long but it should log the precise cause of the
rejection; in this case "'name' or 'expected\_ipvX\_addrs' must be
present" tells us that either the interface's name or its expected IP
address must be specified.

## Creating more security policy

We recommend using selector-based security policy with
bare-metal workloads. This allows ordered policy to be applied to
endpoints that match particular label selectors.

For example, you could add a second policy for webserver access:

```
cat << EOF | dist/calicoctl create -f -
- apiVersion: projectcalico.org/v3
  kind: GlobalNetworkPolicy
  metadata:
    name: webserver
  spec:
    selector: "role==\"webserver\""
    order: 100
    ingress:
    - action: Allow
      protocol: TCP
      destination:
        ports: [80]
    egress:
    - action: Allow
EOF
```

## Failsafe rules

To avoid completely cutting off a host via incorrect or malformed
policy, {{site.prodname}} has a failsafe mechanism that keeps various pinholes open
in the firewall.

By default, {{site.prodname}} keeps the following ports open on *all* host endpoints:

| Port   | Protocol | Direction           |              Purpose                           |
|--------|----------|---------------------|------------------------------------------------|
|   22   |   TCP    |  Inbound            |             SSH access                         |
|   53   |   UDP    |  Outbound           |             DNS queries                        |
|   67   |   UDP    |  Outbound           |             DHCP access                        |
|   68   |   UDP    |  Inbound            |             DHCP access                        |
|   179  |   TCP    |  Inbound & Outbound |             BGP access (Calico networking)     |
|   2379 |   TCP    |  Inbound & Outbound |             etcd access                        |
|   2380 |   TCP    |  Inbound & Outbound |             etcd access                        |
|   6666 |   TCP    |  Inbound & Outbound |             etcd self-hosted service access    |
|   6667 |   TCP    |  Inbound & Outbound |             etcd self-hosted service access    |


The lists of failsafe ports can be configured via the configuration parameters
`FailsafeInboundHostPorts` and `FailsafeOutboundHostPorts`
described in [Configuring
Felix]({{site.baseurl}}/{{page.version}}/reference/felix/configuration).  They
can be disabled by setting each configuration value to "none".

> **Important**: Removing the inbound failsafe rules can leave a host inaccessible.
>
> Removing the outbound failsafe rules can leave Felix unable to connect
> to etcd.
>
> Before disabling the failsafe rules, we recommend creating a policy to
> replace it with more-specific rules for your environment: see
> [above](#creating-basic-connectivity-and-policy).
{: .alert .alert-danger}


## Untracked policy

Policy for host endpoints can be marked as `doNotTrack`.  This means that rules
in that policy should be applied before any data plane connection tracking, and
that packets allowed by these rules should not be tracked.

Untracked policy is designed for allowing untracked connections to a server
process running directly on a host—where, by 'directly', we mean _not_ in a
pod/VM/container workload.  A typical scenario for using `doNotTrack` policy
would be a server, running directly on a host, that accepts a very high rate of
shortlived connections, such as `memcached`.  On Linux, if those connections
are tracked, the conntrack table can fill up and then Linux may drop packets
for further connection attempts, meaning that those newer connections will
fail.  If you are using {{site.prodname}} to secure that server's host, you can avoid this
problem by defining a policy that allows access to the server's ports and is
marked as `doNotTrack`.

Since there is no connection tracking for a `doNotTrack` policy, it is
important that the policy's ingress and egress rules are specified
symmetrically.  For example, for a server on port 999, the policy must include
an ingress rule allowing access *to* port 999 and an egress rule allowing
outbound traffic *from* port 999.  (Whereas for a connection tracked policy, it
is usually enough to specify the ingress rule only, and then connection
tracking will automatically allow the return path.)

Because of how untracked policy is implemented, untracked ingress rules apply
to all incoming traffic through a host endpoint—regardless of where that
traffic is going—but untracked egress rules only apply to traffic that is
sent from the host itself (not from a local workload) out of that host
endpoint.

## Pre-DNAT policy

Policy for host endpoints can be marked as `preDNAT`.  This means that rules in
that policy should be applied before any DNAT (Destination Network Address
Translation), which is useful if it is more convenient to specify {{site.prodname}} policy
in terms of a packet's original destination IP address and port, than in terms
of that packet's destination IP address and port after it has been DNAT'd.

An example is securing access to Kubernetes NodePorts from outside the cluster.
Traffic from outside is addressed to any node's IP address, on a known
NodePort, and Kubernetes (kube-proxy) then DNATs that to the IP address of one
of the pods that provides the corresponding service, and the relevant port
number on that pod (which is usually different from the NodePort).

As NodePorts are the externally advertised way of connecting to services (and a
NodePort uniquely identifies a service, whereas an internal port number may
not), it makes sense to express {{site.prodname}} policy to expose or secure particular
Services in terms of the corresponding NodePorts.  But that is only possible if
the {{site.prodname}} policy is applied before DNAT changes the NodePort to something
else. Hence this kind of policy needs `preDNAT` set to `true`.

In addition to being applied before any DNAT, the enforcement of pre-DNAT
policy differs from that of normal host endpoint policy in three key details,
reflecting that it is designed for the policing of incoming traffic from
outside the cluster:

-  Pre-DNAT policy may only have ingress rules, not egress.  (When incoming
   traffic is allowed by the ingress rules, standard connection tracking is
   sufficient to allow the return path traffic.)

-  Pre-DNAT policy is enforced for all traffic arriving through a host
   endpoint, regardless of where that traffic is going, and - in particular -
   even if that traffic is routed to a local workload on the same host.
   (Whereas normal host endpoint policy is skipped, for traffic going to a
   local workload.)

-  There is no 'default drop' semantic for pre-DNAT policy (as there is for
   normal host endpoint policy).  In other words, if a host endpoint is defined
   but has no pre-DNAT policies that explicitly allow or deny a particular
   incoming packet, that packet is allowed to continue on its way, and will
   then be accepted or dropped according to workload policy (if it is going to
   a local workload) or to normal host endpoint policy (if not).

## Policy on forwarded traffic
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
> Calico will apply this policy after all other policies. Refer to the
> [policy spec]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy#spec) for
> more discussion.
{: .alert .alert-info}

## When do host endpoint policies apply?

As stated above, normal host endpoint policies apply to traffic that arrives on
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

## Host endpoint policy: a worked example

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

Here is the pre-DNAT policy that we need to disallow incoming external traffic
in general:

```
calicoctl apply -f - <<EOF
- apiVersion: projectcalico.org/v3
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
- apiVersion: projectcalico.org/v3
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
allowed by the [failsafe rules](#failsafe-rules)). Because there is no default-deny
rule for forwarded traffic, forwarded traffic will be allowed for host endpoints.

```
calicoctl apply -f - <<EOF
- apiVersion: projectcalico.org/v3
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

```
calicoctl apply -f - <<EOF
- apiVersion: projectcalico.org/v3
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
(except for any [failsafe ports](#failsafe-rules)).  For example, if the
cluster includes a Kubernetes Service that is exposed as NodePort 31852, you
should find, at this point, that that NodePort works from within the cluster,
but not from outside.

To open a pinhole for that NodePort, for external access, you can configure a
pre-DNAT policy like this:

```
calicoctl apply -f - <<EOF
- apiVersion: projectcalico.org/v3
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
          ports: [31852]
    selector: has(host-endpoint)
EOF
```

If you wanted to make that NodePort accessible only through particular nodes, you could achieve that by giving those nodes a particular `host-endpoint` label:

```
      host-endpoint: <special-value>
```

and then using `host-endpoint=='<special-value>'` as the selector of the
`allow-nodeport` policy, instead of `has(host-endpoint)`.

### A note about conntrack

{{site.prodname}} uses Linux's connection tracking ('conntrack') as an important
optimization to its processing.  It generally means that {{site.prodname}} only needs to
check its policies for the first packet in an allowed flow—between a pair of
IP addresses and ports—and then conntrack automatically allows further
packets in the same flow, without {{site.prodname}} rechecking every packet.

This can, however, make it look like a {{site.prodname}} policy is not working as it
should, if policy is changed to disallow a flow that was previously allowed.
If packets were recently exchanged on the previously allowed flow, and so there
is conntrack state for that flow that has not yet expired, that conntrack state
will allow further packets between the same IP addresses and ports, even after
the {{site.prodname}} policy has been changed.

Per {{site.prodname}}'s current implementation, there are two workarounds for this:

- Somehow ensure that no further packets flow between the relevant IP
   addresses and ports until the conntrack state has expired (typically about
   a minute).

- Use the 'conntrack' tool to delete the relevant conntrack state; for example
   `conntrack -D -p tcp --orig-port-dst 80`.

Then you should observe that the new {{site.prodname}} policy is enforced for new packets.
