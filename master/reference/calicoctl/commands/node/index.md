---
title: calicoctl node
---

This section describes the `calicoctl node` commands.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl node' commands

Run `calicoctl node --help` to display the following help menu for the
calicoctl node commands.

```
Usage:
  calicoctl node <command> [<args>...]

    status         View the current status of a Calico node.
    diags          Gather a diagnostics bundle for a Calico node.
    checksystem    Verify the compute host is able to run a Calico node instance.

Options:
  -h --help               Show this screen.

Description:
  Node specific commands for calicoctl.  These commands must be run directly on
  the compute host running the Calico node instance.
  
  See 'calicoctl node <command> --help' to read about a specific subcommand.
```

## Node specific commands

Details on the `calicoctl node` commands are described in the documents linked below
organized by sub command.

-  [calicoctl node status](status.md)
-  [calicoctl node diags](diags.md)
-  [calicoctl node checksystem](checksystem.md)

## See also
-  [Resources](../../resources/README.md) for details on all valid resources, including file format
   and schema
-  [Policy](../../resources/policy.md) for details on the Calico selector-based policy model
-  [calicoctl configuration](../../setup/config.md) for details on configuring `calicoctl` to access
   the Calico datastore.
