---
title: calicoctl migrate
description: Commands for calicoctl migrate. 
canonical_url: '/reference/calicoctl/node/index'
---

This section describes the `calicoctl migrate` commands.

Read the [calicoctl Overview]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl migrate' commands

Run `calicoctl migrate --help` to display the following help menu for the
commands.

```
Usage:
  calicoctl migrate <command> [<args>...]

    export  Export the contents of the etcdv3 datastore to yaml.
    import  Store and convert yaml of resources into the Kubernetes datastore.
    lock    Lock the datastore to prevent changes from occurring during datastore migration.
    unlock  Unlock the datastore to allow changes once the migration is completed.

Options:
  -h --help      Show this screen.

Description:
  Migration specific commands for calicoctl.

  See 'calicoctl migrate <command> --help' to read about a specific subcommand.
```
{: .no-select-button}

## Migrate specific commands

Details on the `calicoctl node` commands are described in the documents linked below
organized by sub command.

-  [calicoctl migrate export]({{ site.baseurl }}/reference/calicoctl/migrate/export)
-  [calicoctl migrate import]({{ site.baseurl }}/reference/calicoctl/migrate/import)
-  [calicoctl migrate lock]({{ site.baseurl }}/reference/calicoctl/migrate/lock)
-  [calicoctl migrate unlock]({{ site.baseurl }}/reference/calicoctl/migrate/unlock)
