# calicoctl command line interface user reference

The command line tool, `calicoctl`, makes it easy to manage Calico network
and security policy.

This user reference is organized in sections based on the top level command options
of calicoctl.

## Top level help

Run `calicoctl --help` to display the following help menu for the top level 
calicoctl commands.

```
Usage:
  calicoctl [options] <command> [<args>...]

    create         Create a resource by filename or stdin.
    replace        Replace a resource by filename or stdin.
    apply          Apply a resource by filename or stdin.  This creates a resource if
                   it does not exist, and replaces a resource if it does exists.
    delete         Delete a resource identified by file, stdin or resource type and name.
    get            Get a resource identified by file, stdin or resource type and name.
    version        Display the version of calicoctl.
    node           Calico node management.
    ipam           IP address management.

Options:
  -h --help               Show this screen.
  -l --log-level=<level>  Set the log level (one of panic, fatal, error,
                          warn, info, debug) [default: panic]

Description:
  The calicoctl command line tool is used to manage Calico network and security policy,
  to view and manage endpoint configuration, and to manage a Calico node instance.

  See 'calicoctl <command> --help' to read about a specific subcommand.```

## Top level command line options

Details on the `calicoctl` commands are described in the documents linked below
organized by top level command.

-  [calicoctl create](create.md)
-  [calicoctl replace](replace.md)
-  [calicoctl apply](apply.md)
-  [calicoctl delete](delete.md)
-  [calicoctl get](get.md)
-  [calicoctl version](version.md)
-  [calicoctl node](node.md)
-  [calicoctl ipam](ipam.md)
