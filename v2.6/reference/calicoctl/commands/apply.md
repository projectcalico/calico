---
title: calicoctl apply
canonical_url: 'https://docs.projectcalico.org/v3.6/reference/calicoctl/commands/apply'
---

This sections describes the `calicoctl apply` command.

Read the [calicoctl command line interface user reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) 
for a full list of calicoctl commands.

> **Note**: The available actions for a specific resource type may be 
> limited based on the datastore used for Calico (etcdv2 / Kubernetes API). 
> Please refer to the 
> [Resources section]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/)
> for details about each resource type.
{: .alert .alert-info}


## Displaying the help text for 'calicoctl apply' command

Run `calicoctl apply --help` to display the following help menu for the 
command.

```
Usage:
  calicoctl apply --filename=<FILENAME> [--config=<CONFIG>]

Examples:
  # Apply a policy using the data in policy.yaml.
  calicoctl apply -f ./policy.yaml

  # Apply a policy based on the JSON passed into stdin.
  cat policy.json | calicoctl apply -f -

Options:
  -h --help                 Show this screen.
  -f --filename=<FILENAME>  Filename to use to apply the resource.  If set to
                            "-" loads from stdin.
  -c --config=<CONFIG>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]

Description:
  The apply command is used to create or replace a set of resources by filename
  or stdin.  JSON and YAML formats are accepted.

  Valid resource types are:

    * node
    * bgpPeer
    * hostEndpoint
    * workloadEndpoint
    * ipPool
    * policy
    * profile

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

### Examples

```
# Apply a set of resources (of mixed type) using the data in resources.yaml.
# Results indicate that 8 resources were successfully applied
$ calicoctl apply -f ./resources.yaml
Successfully applied 8 resource(s)

# Apply two policy resources based on the JSON passed into stdin.
$ cat policy.json | calicoctl apply -f -
Successfully applied 2 'policy' resource(s)
```

### Options

```
-f --filename=<FILENAME>  Filename to use to apply the resource.  If set to
                          "-" loads from stdin.
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
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) for details on the Calico selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup) for details on configuring `calicoctl` to access
   the Calico datastore.
