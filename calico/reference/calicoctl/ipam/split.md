---
title: calicoctl ipam split
description: Command and options for splitting an existing IP pool
canonical_url: '/reference/calicoctl/ipam/split'
---

This section describes the `calicoctl ipam split` command.

Read the [calicoctlOverview]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

## Display the help text for `calicoctl ipam split` command

Run `calicoctl ipam split --help` to display the following help menu for the command.

```
Usage:
  <BINARY_NAME> ipam split <NUMBER> [--cidr=<CIDR>] [--name=<POOL_NAME>] [--config=<CONFIG>] [--allow-version-mismatch]

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection configuration in
                               YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
     --cidr=<CIDR>             CIDR of the IP pool to split.
     --name=<POOL_NAME>        Name of the IP pool to split.
     --allow-version-mismatch  Allow client and cluster versions mismatch.

Description:
  The ipam split command splits an IP pool specified by the specified CIDR or name
  into the specified number of smaller IP pools. Each child IP pool will be of equal
  size. IP pools can only be split into a number of smaller pools that is a power
  of 2.

Examples:
  # Split the IP pool specified by 172.0.0.0/8 into 2 smaller pools
  <BINARY_NAME> ipam split --cidr=172.0.0.0/8 2
```
{: .no-select-button}

### Prerequisites

In order to split an IP pool, you will first need to lock the Calico database
so that no IPAM data can change during the split. This is accomplished by using the
[`calicoctl datastore migrate lock` command]({{ site.baseurl }}/reference/calicoctl/datastore/migrate/lock).
In order to continue normal IPAM operation, you will need to unlock the calico datastore
after the split with the
[`calicoctl datastore migrate unlock` command]({{ site.baseurl }}/reference/calicoctl/datastore/migrate/unlock).

### Examples

Lock the Calico datastore.

```bash
calicoctl datastore migrate lock
```

Split the IP pool specified by 172.0.0.0/15 into 2 smaller pools.

```bash
calicoctl ipam split --cidr=172.0.0.0/15 2
```

This should create 2 IP pools, one covering CIDR `172.0.0.0/16`
and one covering CIDR `172.1.0.0/16`.

Unlock the Calico datastore to restore normal IPAM operation.

```bash
calicoctl datastore migrate unlock
```

### General options

```
  -c --config=<CONFIG>         Path to the file containing connection configuration in
                               YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
```
{: .no-select-button}

## See also
-  [Install calicoctl]({{ site.baseurl }}/maintenance/clis/calicoctl/install)
-  [Resources]({{ site.baseurl }}/reference/resources/overview) for details on all valid resources, including file format
   and schema
