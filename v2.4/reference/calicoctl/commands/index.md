---
title: Command Reference
canonical_url: 'https://docs.projectcalico.org/v3.6/reference/calicoctl/commands/'
---

The command line tool, `calicoctl`, makes it easy to manage Calico network
and security policy.

This section is a command line reference for calicoctl, organised based on 
the command hierarchy.

## Top level help

Run `calicoctl --help` to display the following help menu for the top level 
calicoctl commands.

```
Usage:
  calicoctl [options] <command> [<args>...]

    create    Create a resource by filename or stdin.
    replace   Replace a resource by filename or stdin.
    apply     Apply a resource by filename or stdin.  This creates a resource 
              if it does not exist, and replaces a resource if it does exists.
    delete    Delete a resource identified by file, stdin or resource type and
              name.
    get       Get a resource identified by file, stdin or resource type and 
              name.
    config    Manage system-wide and low-level node configuration options.
    ipam      IP address management.
    node      Calico node management.
    version   Display the version of calicoctl.

Options:
  -h --help               Show this screen.
  -l --log-level=<level>  Set the log level (one of panic, fatal, error,
                          warn, info, debug) [default: panic]

Description:
  The calicoctl command line tool is used to manage Calico network and security
  policy, to view and manage endpoint configuration, and to manage a Calico 
  node instance.

  See 'calicoctl <command> --help' to read about a specific subcommand.
```

## Top level command line options

Details on the `calicoctl` commands are described in the documents linked below
organized by top level command.

-  [calicoctl create]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/create)
-  [calicoctl replace]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/replace)
-  [calicoctl apply]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/apply)
-  [calicoctl delete]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/delete)
-  [calicoctl get]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/get)
-  [calicoctl config]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/config)
-  [calicoctl ipam]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/ipam)
-  [calicoctl node]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node)
-  [calicoctl version]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/version)
