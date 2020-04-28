---
title: calicoctl ipam
description: Commands for calicoctl IP address management (IPAM).
canonical_url: '/reference/calicoctl/ipam/index'
---

This section describes the `calicoctl ipam` commands.

Read the [calicoctl Overview]({{ site.baseurl }}/reference/calicoctl/overview) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl ipam' commands

Run `calicoctl ipam --help` to display the following help menu for the
commands.

```
Usage:
  calicoctl ipam <command> [<args>...]

    release      Release a Calico assigned IP address.
    show         Show details of a Calico assigned IP address,
                 or of overall IP usage.
    configure    Configure IPAM

Options:
  -h --help      Show this screen.

Description:
  IP Address Management specific commands for calicoctl.

  See 'calicoctl ipam <command> --help' to read about a specific subcommand.
```
{: .no-select-button}

## IPAM specific commands

Details on the `calicoctl ipam` commands are described in the documents linked below
organized by sub command.

-  [calicoctl ipam release]({{ site.baseurl }}/reference/calicoctl/ipam/release)
-  [calicoctl ipam show]({{ site.baseurl }}/reference/calicoctl/ipam/show)
-  [calicoctl ipam configure]({{ site.baseurl }}/reference/calicoctl/ipam/configure)
