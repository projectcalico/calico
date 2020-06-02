---
title: calicoctl migrate import
description: Command and options for importing exported data to a kubernetes datastore.
canonical_url: '/reference/calicoctl/migrate/import'
---

This sections describes the `calicoctl migrate import` command.

Read the [calicoctl Overview]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl migrate import' command

Run `calicoctl migrate import --help` to display the following help menu for the
command.

```
Usage:
  calicoctl migrate import --filename=<FILENAME> [--config=<CONFIG>]

Options:
  -h --help                 Show this screen.
  -f --filename=<FILENAME>  Filename to use to import resources.  If set to
                            "-" loads from stdin.
  -c --config=<CONFIG>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]

Description:
  Import the contents of the etcdv3 datastore from the file created by the
  export command.
```
{: .no-select-button}

### Examples

Import the contents of an etcdv3 datastore stored in a file named `etcd-migration`.

```bash
calicoctl migrate import -f etcd-migration
```

### Options

```
-f --filename=<FILENAME>  Filename to use to import resources.  If set to
                            "-" loads from stdin.
```
{: .no-select-button}

### General options

```
-c --config=<CONFIG>     Path to the file containing connection
                         configuration in YAML or JSON format.
                         [default: /etc/calico/calicoctl.cfg]
```
{: .no-select-button}

## See also

-  [Installing calicoctl]({{ site.baseurl }}/getting-started/clis/calicoctl/install)
-  [Resources]({{ site.baseurl }}/reference/resources/overview) for details on all valid resources, including file format
   and schema
-  [Policy]({{ site.baseurl }}/reference/resources/networkpolicy) for details on the {{site.prodname}} selector-based policy model
