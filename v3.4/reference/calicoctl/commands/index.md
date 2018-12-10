---
title: Command Reference
redirect_from: latest/reference/calicoctl/commands/index
canonical_url: 'https://docs.projectcalico.org/v3.3/reference/calicoctl/commands/'
---

The command line tool, `calicoctl`, makes it easy to manage {{site.prodname}} network
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
    convert   Convert config files between different API versions.
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
{: .no-select-button}

## Top level command line options

Details on the `calicoctl` commands are described in the documents linked below
organized by top level command.

-  [calicoctl create]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/create)
-  [calicoctl replace]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/replace)
-  [calicoctl apply]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/apply)
-  [calicoctl delete]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/delete)
-  [calicoctl get]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/get)
-  [calicoctl ipam]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/ipam)
-  [calicoctl node]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/node)
-  [calicoctl convert]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/convert)
-  [calicoctl version]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/version)

## Modifying low-level component configurations

In order to update low-level Felix or BGP settings (`FelixConfiguration` and `BGPConfiguration` resource types):
1. Get the appropriate resource and store the yaml output in a file using `calicoctl get <resource type> <resource name> -o yaml --export > config.yaml`.
1. Modify the saved resource file.
1. Update the resource using `apply` or `replace` command: `calicoctl replace -f config.yaml`.

See [Configuring Felix]({{site.baseurl}}/{{page.version}}/reference/felix/configuration) for more details.
