---
title: calicoctl node
---

This section describes the `calicoctl node` commands.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl/)
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

-  [calicoctl node status]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/status)
-  [calicoctl node diags]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/diags)
-  [calicoctl node checksystem]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node/checksystem)

## See also
-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) for details on the Calico selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/config) for details on configuring `calicoctl` to access
   the Calico datastore.
