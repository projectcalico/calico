---
title: calicoctl datastore migrate lock
description: Command and options for locking a datastore for migration.
canonical_url: '/reference/calicoctl/datastore/migrate/lock'
---

This sections describes the `calicoctl datastore migrate lock` command.

Read the [calicoctl Overview]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

## Display the help text for 'calicoctl datastore migrate unlock' command

Run `calicoctl datastore migrate lock --help` to display the following help menu for the
command.

```
Usage:
  calicoctl datastore migrate lock [--config=<CONFIG>]

Options:
  -h --help                 Show this screen.
  -c --config=<CONFIG>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]

Description:
  Lock the datastore to prepare it for migration. This prevents any new
  Calico resources from affecting the cluster but does not prevent updating
  or creating new Calico resources.
```
{: .no-select-button}

### Examples

Lock the datastore to prepare it for migration so that any changes to the
data will not affect the cluster during migration.

```bash
calicoctl datastore migrate lock
```

### General options

```
-c --config=<CONFIG>     Path to the file containing connection
                         configuration in YAML or JSON format.
                         [default: /etc/calico/calicoctl.cfg]
```
{: .no-select-button}

## See also

-  [Install calicoctl]({{ site.baseurl }}/maintenance/clis/calicoctl/install)
-  [Resources]({{ site.baseurl }}/reference/resources/overview) for details on all valid resources, including file format
   and schema
