---
title: calicoctl node
description: Commands for calicoctl node. 
canonical_url: '/reference/calicoctl/node/index'
---

This section describes the `calicoctl node` commands.

Read the [calicoctl Overview]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

Note that if you run `calicoctl` in a container, `calicoctl node ...` commands will
not work (they need access to parts of the host filesystem).

## Displaying the help text for 'calicoctl node' commands

Run `calicoctl node --help` to display the following help menu for the
commands.

```
Usage:
  calicoctl node <command> [<args>...]

    run          Run the Calico node container image
    status       View the current status of a Calico node.
    diags        Gather a diagnostics bundle for a Calico node.
    checksystem  Verify the compute host is able to run a Calico node instance.

Options:
  -h --help      Show this screen.

Description:
  Node specific commands for calicoctl.  These commands must be run directly on
  the compute host running the Calico node instance.

  See 'calicoctl node <command> --help' to read about a specific subcommand.
```
{: .no-select-button}

## Node specific commands

Details on the `calicoctl node` commands are described in the documents linked below
organized by sub command.

-  [calicoctl node run]({{ site.baseurl }}/reference/calicoctl/node/run)
-  [calicoctl node status]({{ site.baseurl }}/reference/calicoctl/node/status)
-  [calicoctl node diags]({{ site.baseurl }}/reference/calicoctl/node/diags)
-  [calicoctl node checksystem]({{ site.baseurl }}/reference/calicoctl/node/checksystem)
