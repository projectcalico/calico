---
title: calicoctl datastore migrate
description: Commands for calicoctl datastore migrate. 
canonical_url: '/reference/calicoctl/datastore/migrate/index'
---

This section describes the `calicoctl datastore migrate` commands.

Read the [calicoctl Overview]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

## Display the help text for 'calicoctl datastore migrate' commands

Run `calicoctl datastore migrate --help` to display the following help menu for the
commands.

```
Usage:
  calicoctl datastore migrate <command> [<args>...]

    export  Export the contents of the etcdv3 datastore to yaml.
    import  Store and convert yaml of resources into the Kubernetes datastore.
    lock    Lock the datastore to prevent changes from occurring during datastore migration.
    unlock  Unlock the datastore to allow changes once the migration is completed.

Options:
  -h --help      Show this screen.

Description:
  Migration specific commands for calicoctl.

  See 'calicoctl datastore migrate <command> --help' to read about a specific subcommand.
```
{: .no-select-button}

## Migrate specific commands

Details on the `calicoctl datastore migrate` commands are described in the documents linked below
organized by sub command.

-  [calicoctl datastore migrate export]({{ site.baseurl }}/reference/calicoctl/datastore/migrate/export)
-  [calicoctl datastore migrate import]({{ site.baseurl }}/reference/calicoctl/datastore/migrate/import)
-  [calicoctl datastore migrate lock]({{ site.baseurl }}/reference/calicoctl/datastore/migrate/lock)
-  [calicoctl datastore migrate unlock]({{ site.baseurl }}/reference/calicoctl/datastore/migrate/unlock)
