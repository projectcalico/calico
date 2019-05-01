---
title: calicoctl label
canonical_url: 'https://docs.projectcalico.org/v3.7/reference/calicoctl/commands/label'
---

This section describes the `calicoctl label` command.

Read the [calicoctl command line interface user reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/)
for a full list of calicoctl commands.

> **Note**: The available actions for a specific resource type may be
> limited based on the datastore used for {{site.prodname}} (etcdv3 / Kubernetes API).
> Please refer to the
> [Resources section]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/)
> for details about each resource type.
{: .alert .alert-info}


## Displaying the help text for 'calicoctl label' command

Run `calicoctl label --help` to display the following help menu for the
command.

```
Usage:
  calicoctl label (<KIND> <NAME>
  	              ( <key>=<value> [--overwrite] |
  	                <key> --remove )
                  [--config=<CONFIG>] [--namespace=<NS>])

Examples:
  # Label a workload endpoint
  calicoctl label workloadendpoints nginx --namespace=default app=web

  # Label a node and overwrite the original value of key 'cluster'
  calicoctl label nodes node1 cluster=frontend --overwrite

  # Remove label with key 'cluster' of the node
  calicoctl label nodes node1 cluster --remove

Options:
  -h --help                    Show this screen.
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
  -n --namespace=<NS>          Namespace of the resource.
                               Only applicable to NetworkPolicy and WorkloadEndpoint.
                               Uses the default namespace if not specified.
  --overwrite                  If true, overwrite the value when the key is already
                               present in labels. Otherwise reports error when the
                               labeled resource already have the key in its labels.
                               Can not be used with --remove.
  --remove                     If true, remove the specified key in labels of the
                               resource. Reports error when specified key does not
                               exist. Can not be used with --overwrite.

Description:
  The label command is used to add or update a label on a resource. Resource types
  that can be labeled are:

    * bgpConfiguration
    * bgpPeer
    * felixConfiguration
    * globalNetworkPolicy
    * globalNetworkSet
    * hostEndpoint
    * ipPool
    * networkPolicy
    * node
    * profile
    * workloadEndpoint

  The resource type is case insensitive and may be pluralized.

  Attempting to label resources that do not exist will get an error.

  Attempting to remove a label that does not exist in the resource will get an error.

  When labeling a resource on an existing key:
  - gets an error if option --overwrite is not provided.
  - value of the key updates to specified value if option --overwrite is provided.
```
{: .no-select-button}

### Examples

1. Label a node.

   ```bash
   calicoctl label nodes node1 cluster=backend
   ```

   Results indicate that label was successfully applied.

   ```bash
   Successfully set label cluster on nodes node1
   ```
   {: .no-select-button}

1. Label a node and overwrite the original value of key `cluster`.
   ```bash
   calicoctl label nodes node1 cluster=frontend --overwrite
   ```

   Results indicate that label was successfully overwritten.

   ```bash
   Successfully updated label cluster on nodes node1
   ```
   {: .no-select-button}

1. Remove label with key `cluster` from the node.
   ```bash
   calicoctl label nodes node1 cluster --remove
   ```

   Results indicate that the label was successfully removed.

   ```bash
   Successfully removed label cluster from nodes node1.
   ```
   {: .no-select-button}

### Options

```
  -n --namespace=<NS>          Namespace of the resource.
                               Only applicable to NetworkPolicy and WorkloadEndpoint.
                               Uses the default namespace if not specified.
  --overwrite                  If true, overwrite the value when the key is already
                               present in labels. Otherwise reports error when the
                               labeled resource already have the key in its labels.
                               Can not be used with --remove.
  --remove                     If true, remove the specified key in labels of the
                               resource. Reports error when specified key does not
                               exist. Can not be used with --overwrite.
```
{: .no-select-button}

### General options

```
   -c --config=<CONFIG>      Path to the file containing connection
                             configuration in YAML or JSON format.
                             [default: /etc/calico/calicoctl.cfg]
```
{: .no-select-button}

## See also

-  [Installing calicoctl]({{site.baseurl}}/{{page.version}}/getting-started/calicoctl/install)
-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
