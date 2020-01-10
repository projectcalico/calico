---
title: calicoctl user reference
description: The command line interface tool (CLI) to manage Calico network and security policy.
canonical_url: '/reference/calicoctl/index'
---

The command line tool, `calicoctl`, makes it easy to manage {{site.prodname}}
network and security policy, as well as other {{site.prodname}} configurations.

The full list of resources that can be managed, including a description of each,
is described in the [Resource definitions]({{ site.baseurl }}/reference/resources/)
section.

> **Note**: This section provides full reference information for `calicoctl`. To learn
> how to install and configure `calicoctl`, refer to
> [Installing calicoctl]({{ site.baseurl }}/getting-started/calicoctl/install).
{: .alert .alert-info}

The calicoctl command line interface provides a number of resource management
commands to allow you to create, modify, delete, and view the different
{{site.prodname}} resources. This section is a command line reference for
`calicoctl`, organized based on the command hierarchy.

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
    patch     Patch a pre-exisiting resource in place.
    delete    Delete a resource identified by file, stdin or resource type and
              name.
    get       Get a resource identified by file, stdin or resource type and
              name.
    label     Add or update labels of resources.
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

-  [calicoctl create]({{ site.baseurl }}/reference/calicoctl/create)
-  [calicoctl replace]({{ site.baseurl }}/reference/calicoctl/replace)
-  [calicoctl apply]({{ site.baseurl }}/reference/calicoctl/apply)
-  [calicoctl patch]({{ site.baseurl }}/reference/calicoctl/patch)
-  [calicoctl delete]({{ site.baseurl }}/reference/calicoctl/delete)
-  [calicoctl get]({{ site.baseurl }}/reference/calicoctl/get)
-  [calicoctl label]({{ site.baseurl }}/reference/calicoctl/label)
-  [calicoctl convert]({{ site.baseurl }}/reference/calicoctl/convert)
-  [calicoctl ipam]({{ site.baseurl }}/reference/calicoctl/ipam)
-  [calicoctl node]({{ site.baseurl }}/reference/calicoctl/node)
-  [calicoctl version]({{ site.baseurl }}/reference/calicoctl/version)

## Modifying low-level component configurations

In order to update low-level Felix or BGP settings (`FelixConfiguration` and `BGPConfiguration` resource types):
1. Get the appropriate resource and store the yaml output in a file using `calicoctl get <resource type> <resource name> -o yaml --export > config.yaml`.
1. Modify the saved resource file.
1. Update the resource using `apply` or `replace` command: `calicoctl replace -f config.yaml`.

See [Configuring Felix]({{ site.baseurl }}/reference/felix/configuration) for more details.
