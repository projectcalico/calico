> ![warning](../images/warning.png) This document describes an alpha release of calicoctl
>
> See note at top of [calicoctl guide](../README.md) main page.

# User reference for 'calicoctl create' commands

This sections describes the `calicoctl create` command.

Read the [calicoctl command line interface user reference](../calicoctl.md) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl create' command

Run `calicoctl create --help` to display the following help menu for the 
calicoctl create command.

```
Set the ETCD server access information in the environment variables
or supply details in a config file.

Create a resource by filename or stdin.

Usage:
  calicoctl create --filename=<FILENAME> [--skip-exists] [--config=<CONFIG>]

Examples:
  # Create a policy using the data in policy.yaml.
  calicoctl create -f ./policy.yaml

  # Create a policy based on the JSON passed into stdin.
  cat policy.json | calicoctl create -f -

Options:
  -f --filename=<FILENAME>     Filename to use to create the resource.  If set to "-" loads from stdin.
  -s --skip-exists             Skip over and treat as successful any attempts to create an entry that
                               already exists.
  -c --config=<CONFIG>         Filename containing connection configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
```

## calicoctl create

The create command is used to create a set of resources by filename or stdin.  JSON and
YAML formats are accepted.

Attempting to create a resource that already exists is treated as a terminating error unless the
`--skip-exists` flag is set.  If this flag is set, resources that already exist are skipped.
   
The output of the command indicates how many resources were successfully created, and the error
reason if an error occurred.  If the `--skip-exists` flag is set then skipped resources are 
included in the success count.

The resources are created in the order they are specified.  In the event of a failure
creating a specific resource it is possible to work out which resource failed based on the 
number of resources successfully created.

### Examples
```
# Create a set of resources (of mixed type) using the data in resources.yaml.
# Results indicate that 8 resources were successfully created.
$ calicoctl create -f ./resources.yaml
Successfully created 8 resource(s)

# Create the same set of resources reading from stdin.
# Results indicate failure because the first resource (in this case a Profile) already exists.
$ cat resources.yaml | calicoctl apply -f -
Failed to create any resources: resource already exists: Profile(name=profile1)
```


### Options
```
  -f --filename=<FILENAME>     Filename to use to apply the resource.  If set to "-" loads from stdin.
  -s --skip-exists             Skip over and treat as successful any attempts to create an entry that
                               already exists.
```

### General options
```
  -c --config=<CONFIG>         Filename containing connection configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
```

### See also
-  [Resources](../resources/README.md) for details on all valid resources, including file format
   and schema
-  [Policy](../resources/policy.md) for details on the Calico label-based policy model
-  [calicoctl configuration](../general/config.md) for details on configuring `calicoctl` to access
   the Calico datastore.

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico-go/docs/calicoctl/commands/create.md?pixel)](https://github.com/igrigorik/ga-beacon)
