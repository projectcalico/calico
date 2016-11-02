---
title: calicoctl apply
---

This sections describes the `calicoctl apply` command.

Read the [calicoctl command line interface user reference](../calicoctl.md) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl apply' command

Run `calicoctl apply --help` to display the following help menu for the 
calicoctl apply command.

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
  -f --filename=<FILENAME>  Filename to use to apply the resource.  If set to "-" loads from stdin.
  -c --config=<CONFIG>      Filename containing connection configuration in YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]

Description:
  The apply command is used to create or replace a set of resources by filename or stdin.  JSON and
  YAML formats are accepted.

  Valid resource types are node, bgpPeer, hostEndpoint, workloadEndpoint, policy, pool and
  profile.

  When applying a resource:
  -  if the resource does not already exist (as determined by it's primary identifiers)
     then it is created
  -  if the resource already exists then the specification for that resource is replaced
     in it's entirety by the new resource specification.

  The output of the command indicates how many resources were successfully applied, and the error
  reason if an error occurred.

  The resources are applied in the order they are specified.  In the event of a failure
  applying a specific resource it is possible to work out which resource failed based on the
  number of resources successfully applied

  When applying a resource to perform an update, the complete resource spec must be provided,
  it is not sufficient to supply only the fields that are being updated.
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
  -f --filename=<FILENAME>     Filename to use to apply the resource.  If set to "-" loads from stdin.
```

### General options
```
  -c --config=<CONFIG>         Filename containing connection configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
```

## See also
-  [Resources](../resources) for details on all valid resources, including file format
   and schema
-  [Policy](../resources/policy.md) for details on the Calico selector-based policy model
-  [calicoctl configuration](../setup/config.md) for details on configuring `calicoctl` to access
   the Calico datastore.
