> ![warning](../images/warning.png) This document describes an alpha release of calicoctl
>
> See note at top of [calicoctl guide](README.md) main page.

# calicoctl command line interface user reference

The command line tool, `calicoctl`, makes it easy to manage Calico network
and security policy.

This user reference is organized in sections based on the top level command options
of calicoctl.

## Top level help

Run `calicoctl --help` to display the following help menu for the top level 
calicoctl commands.

```
Usage: calicoctl <command> [<args>...]

    create         Create a resource by filename or stdin.
    replace        Replace a resource by filename or stdin.
    apply          Apply a resource by filename or stdin.  This creates a resource if
                   it does not exist, and replaces a resource if it does exists.
    delete         Delete a resource identified by file, stdin or resource type and name.
    get            Get a resource identified by file, stdin or resource type and name.
    config         Manage system configuration.
    version        Display the version of calicoctl.

See 'calicoctl <command> --help' to read about a specific subcommand.
```

## Top level command line options

Details on the `calicoctl` commands are described in the documents linked below
organized by top level command.

-  [calicoctl create](commands/create.md)
-  [calicoctl replace](commands/replace.md)
-  [calicoctl apply](commands/apply.md)
-  [calicoctl delete](commands/delete.md)
-  [calicoctl get](commands/get.md)
-  [calicoctl config](commands/config.md)
-  [calicoctl version](commands/version.md)

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico-go/docs/calicoctl/calicoctl.md?pixel)](https://github.com/igrigorik/ga-beacon)
