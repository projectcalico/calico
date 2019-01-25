---
title: Using Calico to Secure Host Interfaces
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/bare-metal/bare-metal'
---


This guide describes how to use Calico to secure the network interfaces
of the host itself (as opposed to those of any container/VM workloads
that are present on the host). We call such interfaces "host endpoints",
to distinguish them from "workload endpoints".

Calico supports the same rich security policy model for host endpoints
that it supports for workload endpoints. Host endpoints can have labels
and tags, and their labels and tags are in the same "namespace" as those
of workload endpoints. This allows security rules for either type of
endpoint to refer to the other type (or a mix of the two) using labels
and selectors.

Calico does not support setting IPs or policing MAC addresses for host
interfaces, it assumes that the interfaces are configured by the
underlying network fabric.

Calico distinguishes workload endpoints from host endpoints by a
configurable prefix controlled by the `InterfacePrefix` configuration
value, (see: [Calico Configuration]({{site.baseurl}}/{{page.version}}/usage/configuration)). Interfaces that start with the value of
`InterfacePrefix` are assumed to be workload interfaces. Others are
treated as host interfaces.

Calico blocks all traffic to/from workload interfaces by default;
allowing traffic only if the interface is known and policy is in place.
However, for host endpoints, Calico is more lenient; it only polices
traffic to/from interfaces that it's been explicitly told about. Traffic
to/from other interfaces is left alone.

> **NOTE**
>
> If you have a host with workloads on it then traffic that is
>
> :   forwarded to workloads bypasses the policy applied to host
>     endpoints. If that weren't the case, the host endpoint policy
>     would need to be very broad to allow all traffic destined for any
>     possible workload.
>
> ![]({{site.baseurl}}/images/bare-metal-packet-flows.png)

## Overview

To make use of Calico's host endpoint support, you will need to follow
these steps, described in more detail below:

-   create an etcd cluster, if you haven't already
-   install Calico's Felix daemon on each host
-   initialise the etcd database
-   add policy to allow basic connectivity and Calico function
-   create host endpoint objects in etcd for each interface you want
    Calico to police (in a later release, we plan to support interface
    templates to remove the need to explicitly configure
    every interface)
-   insert policy into etcd for Calico to apply
-   decide whether to disable "failsafe SSH/etcd" access.

## Creating an etcd cluster

If you haven't already created an etcd cluster for your Calico
deployment, you'll need to create one.

To create a single-node etcd cluster for testing, download an etcd v2.x
release from [the etcd releases archive](https://github.com/coreos/etcd/releases); we recommend using
the most recent bugfix release. Then follow the instructions on that
page to unpack and run the etcd binary.

To create a production cluster, you should follow the guidance in the
[etcd manual](https://coreos.com/etcd/docs/latest/). In particular, the
[clustering guide](https://coreos.com/etcd/docs/latest/).

## Installing Felix

There are several ways to install Felix.

-   if you are running Ubuntu 14.04, then you can install a version from
    our PPA:

        sudo add-apt-repository ppa:project-calico/calico-<version>
        sudo apt-get update
        sudo apt-get upgrade
        sudo apt-get install calico-felix

    As of writing, &lt;version&gt; should be 1.4.

-   if you are running a RedHat 7-derived distribution, you can install
    from our RPM repository:

        cat > /etc/yum.repos.d/calico.repo <<EOF
        [calico]
        name=Calico Repository
        baseurl=http://binaries.projectcalico.org/rpm_stable/
        enabled=1
        skip_if_unavailable=0
        gpgcheck=1
        gpgkey=http://binaries.projectcalico.org/rpm/key
        priority=97
        EOF

        yum install calico-felix

-   if you are running another distribution, follow the instructions in
    [this document](pyi-bare-metal-install) to use our installer bundle.

Until you initialise the database, Felix will make a regular log that it
is in state "wait-for-ready". The default location for the log file is
`/var/log/calico/felix.log`.

## Initialising the etcd database

Calico doesn't (yet) have a tool to initialise the database for
bare-metal only deplyments. To initialise the database manually, make
sure the `etcdctl` tool (which ships with etcd) is available, then
execute the following command on one of your etcd hosts:

    etcdctl set /calico/v1/Ready true

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
is tailored to your environment. The example commands below show one
example of how you might do that; the commands:

- Add a single policy, which
  - applies to all known endpoints
  - allows inbound ssh access from a defined "management" subnet
  - allows outbound connectivity to etcd on a particular IP; if
    you have multiple etcd servers you should duplicate the rule
    for each destination
  - allows inbound ICMP
  - allows outbound UDP on port 67, for DHCP.

<!-- -->

    etcdctl set /calico/v1/policy/tier/default/policy/failsafe \
       '{
          "selector": "all()",
          "order": 0,

          "inbound_rules": [
            {"protocol": "tcp",
             "dst_ports": [22],
             "src_net": "<your management CIDR>",
             "action": "allow"},
            {"protocol": "icmp", "action": "allow"}
          ],

          "outbound_rules": [
            {"protocol": "tcp",
             "dst_ports": [<your etcd ports>],
             "dst_net": "<your etcd IP>/32",
             "action": "allow"},
            {"protocol": "udp", "dst_ports": [67], "action": "allow"}
          ]
        }'

Once you have such a policy in place, you may want to disable the
[failsafe rules](#failsafe-rules).

> **NOTE**
>
> Packets that reach the end of the list of rules fall-through to the next policy (sorted by the order field).
>
> :   The selector in the policy, `all()`, will match *all* endpoints,
>     including any workload endpoints. If you have workload endpoints as
>     well as host endpoints then you may wish to use a more restrictive
>     selector. For example, you could label management interfaces with
>     label `endpoint_type = management` and then use selector
>     `endpoint_type == "management"`
>
> :   If you are using Calico for networking workloads, you should add
>     inbound and outbound rules to allow BGP, for example:
>
> :   `{"protocol": "tcp", "dst\_ports": \[179\], "action": "allow"}`

## Creating host endpoint objects

For each host endpoint that you want Calico to secure, you'll need to
create a host endpoint object in etcd. At present, this must be done
manually using `etcdctl set <key> <value>`.

There are two ways to specify the interface that a host endpoint should
refer to. You can either specify the name of the interface or its
expected IP address. In either case, you'll also need to know the
hostname of the host that owns the interface.

For example, to secure the interface named `eth0` with IP 10.0.0.1 on
host `my-host`, you could create a host endpoint object at
`/calico/v1/host/<hostname>/endpoint/<endpoint-id>` (where `<hostname>`
is the hostname of the host with the endpoint and `<endpoint-id>` is an
arbitrary name for the interface, such as "data-1" or "management") with
the following data:

    {
      "name": "eth0",
      "expected_ipv4_addrs": ["10.0.0.1"],
      "profile_ids": [<list of profile IDs>],
      "labels": {
        "role": "webserver",
        "environment": "production",
      }
    }

> **NOTE**
>
> Felix tries to detect the correct hostname for a system. It logs
>
> :   out the value it has determined at start-of-day in the following
>     format:
>
> 2015-10-20 17:42:09,813 \[INFO\]\[30149/5\] calico.felix.config 285:
> Parameter FelixHostname (Felix compute host hostname) has value
> 'my-hostname' read from None

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
>
> :   `expected_ipvX_addrs` fields to resolve tags and label selectors
>     to IP addresses. If the `expected_ipvX_addrs` fields are omitted
>     then security rules that use labels and tags will fail to match
>     this endpoint.
>
Or, if you knew that the IP address should be 10.0.0.1, but not the name
of the interface:

    {
      "expected_ipv4_addrs": ["10.0.0.1"],
      "profile_ids": [<list of profile IDs>],
      "labels": {
        "role": "webserver",
        "environment": "production",
      }
    }

After you create host endpoint objects, Felix will start policing
traffic to/from that interface. If you have no policy or profiles in
place, then you should see traffic being dropped on the interface.

> **NOTE**
>
> :   By default, Calico has a failsafe in place that whitelists certain
>     traffic such as ssh. See below for more details on
>     disabling/configuring the failsafe rules.
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

The Calico team recommend using selector-based security policy with
bare-metal workloads. This allows ordered policy to be applied to
endpoints that match particular label selectors.

+For example, you could add a second policy for webserver access:

    etcdctl set /calico/v1/policy/tier/default/policy/webserver \
        '{
           "selector": "role==\"webserver\"",
           "order": 100,
           "inbound_rules": [
             {"protocol": "tcp", "dst_ports": [80], "action": "allow"}
           ],
           "outbound_rules": [
             {"action": "allow"}
           ]
         }'

## Failsafe rules

To avoid completely cutting off a host via incorrect or malformed
policy, Calico has a failsafe mechanism that keeps various pinholes open
in the firewall.

By default, Calico keeps port 22 inbound open on *all* host endpoints,
which allows access to ssh; as well as outbound communication to ports
2379, 2380, 4001 and 7001, which allows access to etcd's default ports.

The lists of failsafe ports can be configured via the configuration
parameters described in [Calico Configuration]({{site.baseurl}}/{{page.version}}/usage/configuration). They can be disabled by setting each configuration value to an empty string.

> **WARNING**
>
> Removing the inbound failsafe rules can leave a host inaccessible.
>
> Removing the outbound failsafe rules can leave Felix unable to connect
> to etcd.
>
> Before disabling the failsafe rules, we recommend creating a policy to
> replace it with more-specific rules for your environment: see [above](#creating-basic-connectivity-and-calico-policy).
