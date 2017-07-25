---
title: Using Calico to Secure Host Interfaces
---

This guide describes how to use Calico to secure the network interfaces
of the host itself (as opposed to those of any container/VM workloads
that are present on the host). We call such interfaces "host endpoints",
to distinguish them from "workload endpoints" (such as containers or VMs).

Calico supports the same rich security policy model for host endpoints
that it supports for workload endpoints.  Host endpoints can have labels, and
their labels are in the same "namespace" as those of workload endpoints. This
allows security rules for either type of endpoint to refer to the other type
(or a mix of the two) using labels and selectors.

Calico does not support setting IPs or policing MAC addresses for host
interfaces, it assumes that the interfaces are configured by the
underlying network fabric.

Calico distinguishes workload endpoints from host endpoints by a configurable
prefix.  Unless you happen to have host interfaces whose name matches the
default for that prefix (`cali`), you won't need to change it.  In case you do,
see the `InterfacePrefix` configuration value at [Configuring
Felix]({{site.baseurl}}/{{page.version}}/reference/felix/configuration).
Interfaces that start with a value listed in `InterfacePrefix` are assumed to
be workload interfaces.  Others are treated as host interfaces.

Calico blocks all traffic to/from workload interfaces by default;
allowing traffic only if the interface is known and policy is in place.
However, for host endpoints, Calico is more lenient; it only polices
traffic to/from interfaces that it's been explicitly told about. Traffic
to/from other interfaces is left alone.

As of Calico v2.1.0, Calico applies host endpoint security policy both to traffic
that is terminated locally, and to traffic that is forwarded between host
endpoints.  Previously, policy was only applied to traffic that was terminated
locally.  The change allows Calico to be used to secure a NAT gateway or router.
Calico supports selector-based policy as normal when running on a gateway or router
allowing for rich, dynamic security policy based on the labels attached to your
workloads.

> **NOTE**
>
> If you have a host with workloads on it then traffic that is forwarded to
> workloads bypasses the policy applied to host endpoints. If that weren't the
> case, the host endpoint policy would need to be very broad to allow all
> traffic destined for any possible workload.
>
> Since version 2.1.0, Calico applies host endpoint policy to traffic that is
> being forwarded between host interfaces.
>
> ![]({{site.baseurl}}/images/bare-metal-packet-flows.png)

## Installation overview

To make use of Calico's host endpoint support, you will need to follow
these steps, described in more detail below:

-   download the calicoctl binary
-   create an etcd cluster, if you haven't already
-   install Calico's Felix daemon on each host
-   initialize the etcd database
-   add policy to allow basic connectivity and Calico function
-   create host endpoint objects in etcd for each interface you want
    Calico to police (in a later release, we plan to support interface
    templates to remove the need to explicitly configure
    every interface)
-   insert policy into etcd for Calico to apply
-   decide whether to disable "failsafe SSH/etcd" access.

### Download the calicoctl binary

Download the calicoctl binary onto your host.

	wget {{site.data.versions[page.version].first.components.calicoctl.download_url}}
	chmod +x calicoctl

This binary should be placed in your `$PATH` so it can be run from any
directory.

## Creating an etcd cluster

If you haven't already created an etcd cluster for your Calico
deployment, you'll need to create one.

To create a single-node etcd cluster for testing, download an etcd v3.x
release from [the etcd releases archive](https://github.com/coreos/etcd/releases); we recommend using
the most recent bugfix release. Then follow the instructions on that
page to unpack and run the etcd binary.

To create a production cluster, you should follow the guidance in the
[etcd manual](https://coreos.com/etcd/docs/latest/). In particular, the
[clustering guide](https://coreos.com/etcd/docs/latest/).

## Installing Felix

{% include ppa_repo_name %}

There are several ways to install Felix.

-   if you are running Ubuntu 14.04 or 16.04, you can install from our PPA:

        sudo add-apt-repository ppa:project-calico/{{ ppa_repo_name }}
        sudo apt-get update
        sudo apt-get upgrade
        sudo apt-get install calico-felix

-   if you are running a RedHat 7-derived distribution, you can install
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

-   if you are running another distribution, follow the instructions in
    [this document](bare-metal-install) to use the calico-felix binary
    directly.

-   if you want to run under docker, you can use `calicoctl node run --node-image=quay.io/calico/node:{{site.data.versions[page.version].first.title}}` to start
    the calico/node container image.  This container packages up the core Calico
    components to provide both Calico networking and network policy.  Running
    the container automatically pre-initializes the etcd database (which the
    other installations methods do not).  See the
    [`calicoctl node run`]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/run)
    guide for details.

Until you initialize the database, Felix will make a regular log that it
is in state "wait-for-ready". The default location for the log file is
`/var/log/calico/felix.log`.

## Initialising the etcd database

If you are using the container-based installation (using the calico/node
container image), the database is initialized as soon as you start the first
node instance.

If you are self-installed you should configure a `node` resource for each
host running Felix.  In this case, the database is initialized after
creating the first `node` resource.  For a deployment that does not include
the Calico/BGP integration, the specification of a node resource just requires
the name of the node;  for most deployments this will be the same as the
hostname.

```
cat << EOF | calicoctl create -f -
- apiVersion: v1
  kind: node
  metadata:
    name: <node name or hostname>
EOF
```

If you check the felix logfile after this step, the logs should
transition from periodic notifications that felix is in state
"wait-for-ready" to a stream of initialisation messages.

## Creating basic connectivity and Calico policy

When a host endpoint is added, if there is no security policy for that
endpoint, Calico will default to denying traffic to/from that endpoint,
except for traffic that is allowed by the [failsafe rules](#failsafe-rules).

While the [failsafe rules](#failsafe-rules) provide protection against removing all
connectivity to a host,

-   they are overly broad in allowing inbound SSH on any interface and
    allowing traffic out to etcd's ports on any interface
-   depending on your network, they may not cover all the ports that are
    required; for example, your network may reply on allowing ICMP,
    or DHCP.

Therefore, we recommend creating a failsafe Calico security policy that
is tailored to your environment. The example command below shows one
example of how you might do that; the command uses `calicoctl` to:

- Create a single policy resource, which
  - applies to all known endpoints
  - allows inbound ssh access from a defined "management" subnet
  - allows outbound connectivity to etcd on a particular IP; if
    you have multiple etcd servers you should duplicate the rule
    for each destination
  - allows inbound ICMP
  - allows outbound UDP on port 67, for DHCP.

When running this command, replace the placeholders in angle brackets with
appropriate values for your deployment.
<!-- -->

```
cat << EOF | calicoctl create -f -
- apiVersion: v1
  kind: policy
  metadata:
    name: failsafe
  spec:
    selector: "all()"
    order: 0
    ingress:
    - action: allow
      protocol: tcp
      source:
        nets:
        - "<your management CIDR>"
      destination:
        ports: [22]
    - action: allow
      protocol: icmp
    egress:
    - action: allow
      protocol: tcp
      destination:
        nets:
        - "<your etcd IP>/32"
        ports: [<your etcd ports>]
    - action: allow
      protocol: udp
      destination:
        ports: [67]
EOF
```

Once you have such a policy in place, you may want to disable the
[failsafe rules](#failsafe-rules).

> **NOTE**
>
> Packets that reach the end of the list of rules fall-through to the next policy (sorted by the order field).
>
> The selector in the policy, `all()`, will match *all* endpoints,
> including any workload endpoints. If you have workload endpoints as
> well as host endpoints then you may wish to use a more restrictive
> selector. For example, you could label management interfaces with
> label `endpoint_type = management` and then use selector
> `endpoint_type == "management"`
>
> If you are using Calico for networking workloads, you should add
> inbound and outbound rules to allow BGP:  add an ingress and egress rule
> to allow TCP traffic to destination port 179.

## Creating host endpoint objects

For each host endpoint that you want Calico to secure, you'll need to
create a host endpoint object in etcd.  Use the `calicoctl create` command
to create a host endpoint resource (hostEndpoint).

There are two ways to specify the interface that a host endpoint should
refer to. You can either specify the name of the interface or its
expected IP address. In either case, you'll also need to know the name given to
the Calico node running on the host that owns the interface; in most cases this
will be the same as the hostname of the host.

For example, to secure the interface named `eth0` with IP 10.0.0.1 on
host `my-host`, run the command below.  The name of the endpoint is an
arbitrary name required for endpoint identification.

When running this command, replace the placeholders in angle brackets with
appropriate values for your deployment.

```
cat << EOF | calicoctl create -f -
- apiVersion: v1
  kind: hostEndpoint
  metadata:
    name: <name of endpoint>
    node: <node name or hostname>
    labels:
      role: webserver
      environment: production
  spec:
    interfaceName: eth0
    profiles: [<list of profile IDs>]
    expectedIPs: ["10.0.0.1"]
EOF
```

> **NOTE**
>
> Felix tries to detect the correct hostname for a system. It logs
> out the value it has determined at start-of-day in the following
> format:
>
> `2015-10-20 17:42:09,813 \[INFO\]\[30149/5\] calico.felix.config 285: Parameter FelixHostname (Felix compute host hostname) has value 'my-hostname' read from None`
>
> The value (in this case "my-hostname") needs to match the hostname
> used in etcd. Ideally, the host's system hostname should be set
> correctly but if that's not possible, the Felix value can be
> overridden with the FelixHostname configuration setting. See
> configuration for more details.

Where `<list of profile IDs>` is an optional list of security profiles
to apply to the endpoint and labels contains a set of arbitrary
key/value pairs that can be used in selector expressions.

<!-- TODO(smc) data-model: Link to new data model docs. -->

> **Warning**
>
> When rendering security rules on other hosts, Calico uses the
> `expectedIPs` field to resolve label selectors
> to IP addresses. If the `expectedIPs` field is omitted
> then security rules that use labels will fail to match
> this endpoint.

Or, if you knew that the IP address should be 10.0.0.1, but not the name
of the interface:

```
cat << EOF | calicoctl create -f -
- apiVersion: v1
  kind: hostEndpoint
  metadata:
    name: <name of endpoint>
    node: <node name or hostname>
    labels:
      role: webserver
      environment: production
  spec:
    profiles: [<list of profile IDs>]
    expectedIPs: ["10.0.0.1"]
EOF
```

After you create host endpoint objects, Felix will start policing
traffic to/from that interface. If you have no policy or profiles in
place, then you should see traffic being dropped on the interface.

> **NOTE**
>
> By default, Calico has a failsafe in place that whitelists certain
> traffic such as ssh. See below for more details on
> disabling/configuring the failsafe rules.
>

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

+For example, you could add a second policy for webserver access:

```
cat << EOF | dist/calicoctl create -f -
- apiVersion: v1
  kind: policy
  metadata:
    name: webserver
  spec:
    selector: "role==\"webserver\""
    order: 100
    ingress:
    - action: allow
      protocol: tcp
      destination:
        ports: [80]
    egress:
    - action: allow
EOF
```

## Failsafe rules

To avoid completely cutting off a host via incorrect or malformed
policy, Calico has a failsafe mechanism that keeps various pinholes open
in the firewall.

By default, Calico keeps port 22 inbound open on *all* host endpoints,
which allows access to ssh; as well as outbound communication to ports
2379, 2380, 4001 and 7001, which allows access to etcd's default ports.

The lists of failsafe ports can be configured via the configuration parameters
described in [Configuring
Felix]({{site.baseurl}}/{{page.version}}/reference/felix/configuration).  They
can be disabled by setting each configuration value to "none".

> **WARNING**
>
> Removing the inbound failsafe rules can leave a host inaccessible.
>
> Removing the outbound failsafe rules can leave Felix unable to connect
> to etcd.
>
> Before disabling the failsafe rules, we recommend creating a policy to
> replace it with more-specific rules for your environment: see [above](#creating-basic-connectivity-and-calico-policy).

## Untracked policy

Policy for host endpoints can be marked as 'doNotTrack'.  This means that rules
in that policy should be applied before any data plane connection tracking, and
that packets allowed by these rules should not be tracked.

Untracked policy is designed for allowing untracked connections to a server
process running directly on a host - where by 'directly' we mean _not_ in a
pod/VM/container workload.  A typical scenario for using 'doNotTrack' policy
would be a server, running directly on a host, that accepts a very high rate of
shortlived connections, such as `memcached`.  On Linux, if those connections
are tracked, the conntrack table can fill up and then Linux may drop packets
for further connection attempts, meaning that those newer connections will
fail.  If you are using Calico to secure that server's host, you can avoid this
problem by defining a policy that allows access to the server's ports and is
marked as 'doNotTrack'.

Since there is no connection tracking for a 'doNotTrack' policy, it is
important that the policy's ingress and egress rules are specified
symmetrically.  For example, for a server on port 999, the policy must include
an ingress rule allowing access *to* port 999 and an egress rule allowing
outbound traffic *from* port 999.  (Whereas for a connection tracked policy, it
is usually enough to specify the ingress rule only, and then connection
tracking will automatically allow the return path.)

Because of how untracked policy is implemented, untracked ingress rules apply
to all incoming traffic through a host endpoint - regardless of where that
traffic is going - but untracked egress rules only apply to traffic that is
sent from the host itself (not from a local workload) out of that host
endpoint.

## Pre-DNAT policy

Policy for host endpoints can be marked as 'preDNAT'.  This means that rules in
that policy should be applied before any DNAT (Destination Network Address
Translation), which is useful if it is more convenient to specify Calico policy
in terms of a packet's original destination IP address and port, than in terms
of that packet's destination IP address and port after it has been DNAT'd.

An example is securing access to Kubernetes NodePorts from outside the cluster.
Traffic from outside is addressed to any node's IP address, on a known
NodePort, and Kubernetes (kube-proxy) then DNATs that to the IP address of one
of the pods that provides the corresponding Service, and the relevant port
number on that pod (which is usually different from the NodePort).

As NodePorts are the externally advertised way of connecting to Services (and a
NodePort uniquely identifies a Service, whereas an internal port number may
not), it makes sense to express Calico policy to expose or secure particular
Services in terms of the corresponding NodePorts.  But that is only possible if
the Calico policy is applied before DNAT changes the NodePort to something
else - and hence this kind of policy needs 'preDNAT' set to true.

In addition to being applied before any DNAT, the enforcement of pre-DNAT
policy differs from that of normal host endpoint policy in three key details,
reflecting that it is designed for the policing of incoming traffic from
outside the cluster:

1. Pre-DNAT policy may only have ingress rules, not egress.  (When incoming
   traffic is allowed by the ingress rules, standard connection tracking is
   sufficient to allow the return path traffic.)

2. Pre-DNAT policy is enforced for all traffic arriving through a host
   endpoint, regardless of where that traffic is going, and - in particular -
   even if that traffic is routed to a local workload on the same host.
   (Whereas normal host endpoint policy is skipped, for traffic going to a
   local workload.)

3. There is no 'default drop' semantic for pre-DNAT policy (as there is for
   normal host endpoint policy).  In other words, if a host endpoint is defined
   but has no pre-DNAT policies that explicitly allow or deny a particular
   incoming packet, that packet is allowed to continue on its way, and will
   then be accepted or dropped according to workload policy (if it is going to
   a local workload) or to normal host endpoint policy (if not).

## When do host endpoint policies apply?

As stated above, normal host endpoint policies apply to traffic that arrives on
and/or is sent to a host interface, except if that traffic comes from or is
destined for a workload on the same host; but the rules for applying untracked
and pre-DNAT policies are different in some cases.  Here we present and
summarize all of those rules together, for all possible flows and all types of
host endpoints policy.

For packets that arrive on a host interface and are destined for a local
workload - i.e. a locally-hosted pod, container or VM:

- Pre-DNAT policies apply.

- Normal policies do not apply - by design, because Calico enforces the
  destination workload's ingress policy in this case.

- Untracked policies technically do apply, but never have any net positive
  effect for such flows.

  > **NOTE**
  >
  > To be precise, untracked policy for the incoming host interface may apply
  > in the forwards direction, and if so it will have the effect of forwarding
  > the packet to the workload without any connection tracking.  But then, in
  > the reverse direction, there will be no conntrack state for the return
  > packets to match, and there is no application of any egress rules that may
  > be defined by the untracked policy - so unless the workload's policy
  > specifically allows the relevant source IP, the return packet will be
  > dropped.  That is the same overall result as if there was no untracked
  > policy at all, so in practice it is as if untracked policies do not apply
  > to this flow.

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

- Normal policies apply, specifically the ingress rules of the normal policies
  that apply to interface A, and the egress rules of the normal policies that
  apply to interface B.  (The reverse direction is allowed by conntrack state.)

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

- No host endpoint policies apply.

## Pre-DNAT policy: a worked example

Imagine a Kubernetes cluster, that its administrator wants to secure as much as
possible against incoming traffic from outside the cluster.  Let's suppose that:

- The cluster provides various useful Services that are exposed as Kubernetes
  NodePorts - i.e. as well-known TCP port numbers that appear to be available
  on any node in the cluster.

- Most of those Services, however, should not be accessed from outside the
  cluster via _any_ node, but instead via a LoadBalancer IP that is routable
  from outside the cluster and maps to one of just a few 'ingress' nodes.  (The
  LoadBalancer IP is a virtual IP that, at any given time, gets routed somehow
  to one of those 'ingress' nodes.)

- For a few Services, on the other hand, there is no LoadBalancer IP set up, so
  those Services should be accessible from outside the cluster through their
  NodePorts on any node.

- All other incoming traffic from outside the cluster should be disallowed.

![]({{site.baseurl}}/images/bare-metal-example.png)

For each Service in the first set, we want to allow traffic from outside the
cluster that is addressed to `<service-load-balancer-ip>:<service-port>`, but
only when it enters the cluster through one of the 'ingress' nodes.  For each
Service in the second set, we want to allow traffic from outside the cluster
that is addressed to `<node-ip>:<service-node-port>`, via any node.

We can do this by applying Calico pre-DNAT policy to the external interfaces of
each cluster node.  We use pre-DNAT policy, rather than normal host endpoint
policy, for two reasons:

1. Normal host endpoint policy is not enforced for incoming traffic to a local
   pod, whereas pre-DNAT policy is enforced for _all_ incoming traffic.  Here
   we want to police all incoming traffic from outside the cluster, regardless
   of its destination, so pre-DNAT is the right choice.

2. We want to express our policy in terms of the external port numbers
   `<service-port>` and `<service-node-port>`.  The kube-proxy on the ingress
   node will use DNATs to change those port numbers (and IP addresses) to those
   of one of the pods that backs the relevant Service.  Our policy therefore
   needs to be enforced _before_ those DNATs, and of course that is exactly
   what pre-DNAT policy is for.

Let's begin with the policy to disallow incoming traffic by default.  Every
outward interface of each node, by which traffic from outside could possibly
enter the cluster, must be defined as a Calico host endpoint; for example, for
`eth0` on `node1`:

```
apiVersion: v1
kind: hostEndpoint
metadata:
  name: node1-eth0
  node: node1
  labels:
    host-endpoint: ingress
spec:
  interfaceName: eth0
```

The nodes that are allowed as load balancer ingress nodes should have an
additional label to indicate that, let's say `load-balancer-ingress: true`.

Then we can deny all incoming traffic through those interfaces, unless it is
from a source IP that is known to be within the cluster.  (Note: we are
assuming that the same interfaces can also be used for traffic that is
forwarded from other nodes or pods in the cluster - as would be the case for
nodes with only one external interface.)

```
apiVersion: v1
kind: policy
metadata:
  name: disallow-incoming
spec:
  preDNAT: true
  order: 100
  ingress:
    - action: deny
      source:
        notNets: [<pod-cidr>, <cluster-internal-node-cidr>, ...]
  selector: host-endpoint=='ingress'
```

Now, to allow traffic through the load balancer ingress nodes to
`<service-load-balancer-ip>:<service-port>` (for each load-balanced Service):

```
apiVersion: v1
kind: policy
metadata:
  name: allow-load-balancer-service-1
spec:
  preDNAT: true
  order: 90
  ingress:
    - action: allow
      destination:
        nets: [<service-load-balancer-ip>]
        ports: [<service-port>]
  selector: load-balancer-ingress=='true'
```

And for traffic to NodePorts - for each non-load-balanced Service - via any
node:

```
apiVersion: v1
kind: policy
metadata:
  name: allow-node-port-service-1
spec:
  preDNAT: true
  order: 90
  ingress:
    - action: allow
      destination:
        ports: [<node-port>]
  selector: host-endpoint=='ingress'
```

And that completes the example.  It's worth re-emphasizing, though, two key
points about the application of pre-DNAT policy that make this work; especially
as pre-DNAT policy differs on these points from normal host endpoint policy.

Firstly, there is no 'default drop' semantic for pre-DNAT policy, like there
_is_ for normal policy.  So, if policies are defined such that _some_ pre-DNAT
policies apply to a host endpoint, but none of those policies matches a
particular incoming packet, that packet is allowed to continue on its way.
(Whereas if there are normal policies that apply to a host endpoint, and
none of those policies matches a packet, that packet will be dropped.)

For the example here, that means that we can specify some pre-DNAT policy,
applying to all of the cluster's external interfaces, without having to
enumerate and explicitly _allow_ all of the internal flows that may also go
through those interfaces.  It's also why the second point works...

Namely, that if traffic comes in through a host endpoint and is routed to a
local workload, any host endpoint pre-DNAT policy is enforced as well as the
ingress policy for that workload - whereas normal host endpoint policy is
skipped in that scenario.  (Normal host endpoint policy is 'trumped' by
workload policy, for packets going to a local workload.)

For the example here, that means that the last pre-DNAT policy above does not
accidentally expose workloads that happen to use the same `<node-port>`, or
that provide the backing for `<node-port>`, unless those workloads' own policy
allows that.
