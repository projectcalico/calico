---
title: calicoctl delete
description: Command to delete a policy.
canonical_url: '/reference/calicoctl/delete'
---

This sections describes the `calicoctl delete` command.

Read the [calicoctl command line interface user reference]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

> **Note**: The available actions for a specific resource type may be
> limited based on the datastore used for {{site.prodname}} (etcdv3 / Kubernetes API).
> Please refer to the
> [Resources section]({{ site.baseurl }}/reference/resources/overview)
> for details about each resource type.
{: .alert .alert-info}

## Displaying the help text for 'calicoctl delete' command

Run `calicoctl delete --help` to display the following help menu for the
command.

```
Usage:
  calicoctl delete ( (<KIND> [<NAME...>]) |
                   --filename=<FILE>) [--recursive] [--skip-empty]
                   [--skip-not-exists] [--config=<CONFIG>] [--namespace=<NS>]

Examples:
  # Delete a policy using the type and name specified in policy.yaml.
  calicoctl delete -f ./policy.yaml

  # Delete a policy based on the type and name in the YAML passed into stdin.
  cat policy.yaml | calicoctl delete -f -

  # Delete policies with names "foo" and "bar"
  calicoctl delete policy foo bar

Options:
  -h --help                 Show this screen.
  -s --skip-not-exists      Skip over and treat as successful, resources that
                            don't exist.
  -f --filename=<FILENAME>  Filename to use to delete the resource.  If set to
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
                            Uses the default namespace if not specified.
  --context=<context>       The name of the kubeconfig context to use.

Description:
  The delete command is used to delete a set of resources by filename or stdin,
  or by type and identifiers.  JSON and YAML formats are accepted for file and
  stdin format.

  Valid resource types are:

    * bgpConfiguration
    * bgpPeer
    * felixConfiguration
    * globalNetworkPolicy
    * hostEndpoint
    * ipPool
    * networkPolicy
    * node
    * profile
    * workloadEndpoint

  The resource type is case insensitive and may be pluralized.

  Attempting to delete a resource that does not exists is treated as a
  terminating error unless the --skip-not-exists flag is set.  If this flag is
  set, resources that do not exist are skipped.

  When deleting resources by type, only a single type may be specified at a
  time.  The name is required along with any and other identifiers required to
  uniquely identify a resource of the specified type.

  The output of the command indicates how many resources were successfully
  deleted, and the error reason if an error occurred.  If the --skip-not-exists
  flag is set then skipped resources are included in the success count.

  The resources are deleted in the order they are specified.  In the event of a
  failure deleting a specific resource it is possible to work out which
  resource failed based on the number of resources successfully deleted.
```
{: .no-select-button}

### Examples

1. Delete a set of resources (of mixed type) using the data in resources.yaml.

   ```bash
   calicoctl delete -f ./resources.yaml
   ```

   Results indicate that 8 resources were successfully deleted.

   ```
   Successfully deleted 8 resource(s)
   ```
   {: .no-select-button}

1. Delete a policy resource by name.  The policy is called "policy1".

   ```bash
   bin/calicoctl delete policy policy1
   ```

   Results indicate success.

   ```
   Successfully deleted 1 'policy' resource(s)
   ```
   {: .no-select-button}

### Options

```
-s --skip-not-exists      Skip over and treat as successful, resources that
                          don't exist.
-f --filename=<FILENAME>  Filename to use to delete the resource.  If set to
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

-  [Installing calicoctl]({{ site.baseurl }}/maintenance/clis/calicoctl/install).
-  [Resources]({{ site.baseurl }}/reference/resources/overview) for details on all valid resources, including file format
   and schema
-  [NetworkPolicy]({{ site.baseurl }}/reference/resources/networkpolicy) for details on the {{site.prodname}} selector-based policy model
