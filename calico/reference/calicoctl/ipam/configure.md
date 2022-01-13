---
title: calicoctl ipam
description: Command to change IPAM configuration.
canonical_url: '/reference/calicoctl/ipam/configure'
---

This section describes the `calicoctl ipam configure` command.

Read the [calicoctl overview]({{ site.baseurl }}/reference/calicoctl/overview) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl ipam configure' command

Run `calicoctl ipam configure --help` to display the following help menu for the
command.

```
Usage:
  calicoctl ipam configure --strictaffinity=<true/false> [--config=<CONFIG>]

Options:
  -h --help                        Show this screen.
     --strictaffinity=<true/false> Set StrictAffinity to true/false. When StrictAffinity
                                   is true, borrowing IP addresses is not allowed.
  -c --config=<CONFIG>             Path to the file containing connection configuration in
                                   YAML or JSON format.
                                   [default: /etc/calico/calicoctl.cfg]

Description:
 Modify configuration for Calico IP address management.
```
{: .no-select-button}

### Examples

```bash
calicoctl ipam configure --strictaffinity=true
```

### General options

```
-c --config=<CONFIG>      Path to the file containing connection
                          configuration in YAML or JSON format.
                          [default: /etc/calico/calicoctl.cfg]
```
{: .no-select-button}

## See also

-  [Installing calicoctl]({{ site.baseurl }}/maintenance/clis/calicoctl/install)