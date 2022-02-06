---
title: calicoctl datastore migrate unlock
description: Command and options for unlocking a datastore after migration.
canonical_url: '/reference/calicoctl/datastore/migrate/unlock'
---

This sections describes the `calicoctl datastore migrate lock` command.

Read the [calicoctl Overview]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

## Display the help text for 'calicoctl datastore migrate unlock' command

Run `calicoctl datastore migrate unlock --help` to display the following help menu for the
command.

```
Usage:
  calicoctl datastore migrate unlock [--config=<CONFIG>]

Options:
  -h --help                 Show this screen.
  -c --config=<CONFIG>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]

Description:
  Unlock the datastore to complete migration. This once again allows
  Calico resources to take effect in the cluster.
```
{: .no-select-button}

### Examples

Unlock the datastore after migration to allow the Calico resources to affect
the cluster.

```bash
calicoctl datastore migrate unlock
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
