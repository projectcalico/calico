---
title: calicoctl delete
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/reference/calicoctl/commands/delete'
---

This sections describes the `calicoctl delete` command.

Read the [calicoctl command line interface user reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) 
for a full list of calicoctl commands.

> **Note**: The available actions for a specific resource type may be 
> limited based on the datastore used for {{site.prodname}} (etcdv3 / Kubernetes API). 
> Please refer to the 
> [Resources section]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/)
> for details about each resource type.
{: .alert .alert-info}


## Displaying the help text for 'calicoctl delete' command

Run `calicoctl delete --help` to display the following help menu for the 
command.

```
Usage:
  calicoctl delete ( (<KIND> [<NAME>]) |
                   --filename=<FILE>)
                   [--skip-not-exists] [--config=<CONFIG>] [--namespace=<NS>]

Examples:
  # Delete a policy using the type and name specified in policy.yaml.
  calicoctl delete -f ./policy.yaml

  # Delete a policy based on the type and name in the YAML passed into stdin.
  cat policy.yaml | calicoctl delete -f -

  # Delete policy with name "foo"
  calicoctl delete policy foo

Options:
  -h --help                 Show this screen.
  -s --skip-not-exists      Skip over and treat as successful, resources that
                            don't exist.
  -f --filename=<FILENAME>  Filename to use to delete the resource.  If set to
                            "-" loads from stdin.
  -c --config=<CONFIG>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]
  -n --namespace=<NS>       Namespace of the resource.
                            Only applicable to NetworkPolicy and WorkloadEndpoint.
                            Uses the default namespace if not specified.

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

### Examples

```
# Delete a set of resources (of mixed type) using the data in resources.yaml.
# Results indicate that 8 resources were successfully deleted.
$ calicoctl delete -f ./resources.yaml
Successfully deleted 8 resource(s)

# Delete a policy resource by name.  The policy is called "policy1".
$ bin/calicoctl delete policy policy1
Successfully deleted 1 'policy' resource(s)
```

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

### General options

```
-c --config=<CONFIG>      Path to the file containing connection
                          configuration in YAML or JSON format.
                          [default: /etc/calico/calicoctl.cfg]
```

## See also

-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
-  [NetworkPolicy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy) for details on the {{site.prodname}} selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup) for details on configuring `calicoctl` to access
   the {{site.prodname}} datastore.
