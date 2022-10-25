---
title: Creating host endpoint objects
description: To protect a host interface, start by creating a host endpoint object in etcd. 
canonical_url: '/reference/host-endpoints/objects'
---

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

```bash
calicoctl create -f - <<EOF
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

```bash
calicoctl create -f - <<EOF
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

> **Note**: By default, {{site.prodname}} has a failsafe in place that allows certain
> traffic such as ssh. See below for more details on
> disabling/configuring the failsafe rules.
{: .alert .alert-info}

If you don't see traffic being dropped, check the hostname, IP address
and (if used) the interface name in the configuration. If there was
something wrong with the endpoint data, Felix will log a validation
error at `WARNING` level and it will ignore the endpoint:

A `grep` through the Felix logs for the string "Validation failed" should allow
you to locate the error.

```bash
grep "Validation failed" /var/log/calico/felix.log
```

An example error follows.

```
2016-05-31 12:16:21,651 [WARNING][8657/3] calico.felix.fetcd 1017:
    Validation failed for host endpoint HostEndpointId<eth0>, treating as
    missing: 'name' or 'expected_ipvX_addrs' must be present.;
    '{ "labels": {"foo": "bar"}, "profile_ids": ["prof1"]}'
```
{: .no-select-button}

The error can be quite long but it should log the precise cause of the
rejection; in this case `'name' or 'expected\_ipvX\_addrs' must be
present` tells us that either the interface's name or its expected IP
address must be specified.
