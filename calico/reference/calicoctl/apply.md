---
title: calicoctl apply
description: Command to apply a policy. 
canonical_url: '/reference/calicoctl/apply'
---

This sections describes the `calicoctl apply` command.

Read the [calicoctl command line interface user reference]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

> **Note**: The available actions for a specific resource type may be
> limited based on the datastore used for {{site.prodname}} (etcdv3 / Kubernetes API).
> Please refer to the
> [Resources section]({{ site.baseurl }}/reference/resources/overview)
> for details about each resource type.
{: .alert .alert-info}

## Displaying the help text for 'calicoctl apply' command

Run `calicoctl apply --help` to display the following help menu for the
command.

```
Usage:
  calicoctl apply --filename=<FILENAME> [--recursive] [--skip-empty] [--config=<CONFIG>] [--namespace=<NS>]

Examples:
  # Apply a policy using the data in policy.yaml.
  calicoctl apply -f ./policy.yaml

  # Apply a policy based on the JSON passed into stdin.
  cat policy.json | calicoctl apply -f -

Options:
  -h --help                 Show this screen.
  -f --filename=<FILENAME>  Filename to use to apply the resource.  If set to
                            "-" loads from stdin. If filename is a directory, this command is
                            invoked for each .json .yaml and .yml file within that directory,
                            terminating after the first failure.
  -R --recursive            Process the filename specified in -f or --filename recursively.
     --skip-empty           Do not error if any files or directory specified using -f or --filename contain no
                            data.
  -c --config=<CONFIG>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]
  -n --namespace=<NS>       Namespace of the resource.
                            Only applicable to NetworkPolicy and WorkloadEndpoint.
                            Only applicable to NetworkPolicy, NetworkSet, and WorkloadEndpoint.
                            Uses the default namespace if not specified.
  --context=<context>       The name of the kubeconfig context to use.

Description:
  The apply command is used to create or replace a set of resources by filename
  or stdin.  JSON and YAML formats are accepted.

  Valid resource types are:

    * bgpConfiguration
    * bgpPeer
    * felixConfiguration
    * globalNetworkPolicy
    * hostEndpoint
    * ipPool
    * networkPolicy
    * networkSet
    * node
    * profile
    * workloadEndpoint

  When applying a resource:
  -  if the resource does not already exist (as determined by it's primary
     identifiers) then it is created
  -  if the resource already exists then the specification for that resource is
     replaced in it's entirety by the new resource specification.

  The output of the command indicates how many resources were successfully
  applied, and the error reason if an error occurred.

  The resources are applied in the order they are specified.  In the event of a
  failure applying a specific resource it is possible to work out which
  resource failed based on the number of resources successfully applied

  When applying a resource to perform an update, the complete resource spec
  must be provided, it is not sufficient to supply only the fields that are
  being updated.
```
{: .no-select-button}

### Examples

1. Apply a set of resources (of mixed type) using the data in resources.yaml.

   ```bash
   calicoctl apply -f ./resources.yaml
   ```

   Results indicate that 8 resources were successfully applied

   ```
   Successfully applied 8 resource(s)
   ```
   {: .no-select-button}

1. Apply two policy resources based on the JSON passed into stdin.

   ```bash
   cat policy.json | calicoctl apply -f -
   ```

   Results indicate success.

   ```
   Successfully applied 2 'policy' resource(s)
   ```
   {: .no-select-button}

### Options

```
-f --filename=<FILENAME>  Filename to use to apply the resource.  If set to
                          "-" loads from stdin.
-n --namespace=<NS>       Namespace of the resource.
                          Only applicable to NetworkPolicy and WorkloadEndpoint.
                          Uses the default namespace if not specified.
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

-  [Installing calicoctl]({{ site.baseurl }}/maintenance/clis/calicoctl/install)
-  [Resources]({{ site.baseurl }}/reference/resources/overview) for details on all valid resources, including file format
   and schema
-  [NetworkPolicy]({{ site.baseurl }}/reference/resources/networkpolicy) for details on the {{site.prodname}} selector-based policy model
