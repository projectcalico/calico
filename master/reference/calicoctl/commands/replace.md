---
title: calicoctl replace
---

This sections describes the `calicoctl replace` command.

Read the [calicoctl command line interface user reference](../calicoctl.md) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl replace' command

Run `calicoctl replace --help` to display the following help menu for the 
calicoctl replace command.

```
Usage:
  calicoctl replace --filename=<FILENAME> [--config=<CONFIG>]

Examples:
  # Replace a policy using the data in policy.yaml.
  calicoctl replace -f ./policy.yaml

  # Replace a policy based on the JSON passed into stdin.
  cat policy.json | calicoctl replace -f -

Options:
  -h --help                  Show this screen.
  -f --filename=<FILENAME>   Filename to use to replace the resource.  If set to "-" loads from stdin.
  -c --config=<CONFIG>       Filename containing connection configuration in YAML or JSON format.
                             [default: /etc/calico/calicoctl.cfg]

Description:
  The replace command is used to replace a set of resources by filename or stdin.  JSON and
  YAML formats are accepted.

  Valid resource types are node, bgpPeer, hostEndpoint, workloadEndpoint, policy, pool and
  profile.

  Attempting to replace a resource that does not exist is treated as a terminating error.

  The output of the command indicates how many resources were successfully replaced, and the error
  reason if an error occurred.

  The resources are replaced in the order they are specified.  In the event of a failure
  replacing a specific resource it is possible to work out which resource failed based on the
  number of resources successfully replaced.

  When replacing a resource, the complete resource spec must be provided, it is not sufficient
  to supply only the fields that are being updated.
```

### Examples
```
# Replace a set of resources (of mixed type) using the data in resources.yaml.
# Results indicate that 8 resources were successfully replaced.
$ calicoctl replace -f ./resources.yaml
Successfully replaced 8 resource(s)

# Replace a policy based on the JSON passed into stdin.
# Results indicate the policy does not exist.
$ cat policy.json | calicoctl replace -f -
Failed to replace any 'policy' resources: resource does not exist: Policy(name=dbPolicy)
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

### See also
-  [Resources](../resources/README.md) for details on all valid resources, including file format
   and schema
-  [Policy](../resources/policy.md) for details on the Calico selector-based policy model
-  [calicoctl configuration](../general/config.md) for details on configuring `calicoctl` to access
   the Calico datastore.

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico-go/docs/calicoctl/commands/replace.md?pixel)](https://github.com/igrigorik/ga-beacon)
