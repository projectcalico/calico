---
title: calicoctl datastore migrate export
description: Command and options for exporting an etcdv3 datastore.
canonical_url: '/reference/calicoctl/datastore/migrate/export'
---

This sections describes the `calicoctl datastore migrate export` command.

Read the [calicoctl Overview]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

## Display the help text for 'calicoctl datastore migrate export' command

Run `calicoctl datastore migrate export --help` to display the following help menu for the
command.

```
Usage:
  calicoctl datastore migrate export [--config=<CONFIG>]

Options:
  -h --help                 Show this screen.
  -c --config=<CONFIG>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]

Description:
  Export the contents of the etcdv3 datastore.  Resources will be exported
  in yaml and json format. Save the results of this command to a file for
  later use with the import command.

  The resources exported include the following:
    - IPAMBlocks
    - BlockAffinities
    - IPAMHandles
    - IPAMConfigurations
    - IPPools
    - BGPConfigurations
    - BGPPeers
    - ClusterInformations
    - FelixConfigurations
    - GlobalNetworkPolicies
    - GlobalNetworkSets
    - HostEndpoints
    - KubeControllersConfigurations
    - NetworkPolicies
    - Networksets
    - Nodes

  The following resources are not exported:
    - WorkloadEndpoints
    - Profiles
```
{: .no-select-button}

### Exported resources

The `export` subcommand exports the following Calico resources:
- IPAMBlocks
- BlockAffinities
- IPAMHandles
- IPAMConfigurations
- IPPools
- BGPConfigurations
- BGPPeers
- ClusterInformations
- FelixConfigurations
- GlobalNetworkPolicies
- GlobalNetworkSets
- HostEndpoints
- NetworkPolicies
- Networksets
- Nodes

The `export` subcommand does not export the following resources
since they should be generated:
- WorkloadEndpoints
- Profiles

### Examples

Export the contents of an etcdv3 datastore to a file named `etcd-migration`.

```bash
calicoctl datastore migrate export > etcd-migration
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
