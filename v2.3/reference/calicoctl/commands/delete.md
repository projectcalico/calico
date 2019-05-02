---
title: calicoctl delete
canonical_url: 'https://docs.projectcalico.org/v3.7/reference/calicoctl/commands/delete'
---

This sections describes the `calicoctl delete` command.

Read the [calicoctl command line interface user reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl delete' command

Run `calicoctl delete --help` to display the following help menu for the 
command.

```
Usage:
  calicoctl delete ([--scope=<SCOPE>] [--node=<NODE>] [--orchestrator=<ORCH>]
                    [--workload=<WORKLOAD>] (<KIND> [<NAME>]) |
                   --filename=<FILE>)
                   [--skip-not-exists] [--config=<CONFIG>]

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
  -n --node=<NODE>          The node (this may be the hostname of the compute
                            server if your installation does not explicitly set
                            the names of each Calico node).
     --orchestrator=<ORCH>  The orchestrator (valid for workload endpoints).
     --workload=<WORKLOAD>  The workload (valid for workload endpoints).
     --scope=<SCOPE>        The scope of the resource type.  One of global,
                            node.  This is only valid for BGP peers and is used
                            to indicate whether the peer is a global peer or
                            node-specific.
  -c --config=<CONFIG>      Path to the file containing connection
                            configuration in YAML or JSON format.
                            [default: /etc/calico/calicoctl.cfg]

Description:
  The delete command is used to delete a set of resources by filename or stdin,
  or by type and identifiers.  JSON and YAML formats are accepted for file and
  stdin format.

  Valid resource types are:

    * node
    * bgpPeer
    * hostEndpoint
    * workloadEndpoint
    * ipPool
    * policy
    * profile

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
-n --node=<NODE>          The node (this may be the hostname of the compute
                          server if your installation does not explicitly set
                          the names of each Calico node).
   --orchestrator=<ORCH>  The orchestrator (valid for workload endpoints).
   --workload=<WORKLOAD>  The workload (valid for workload endpoints).
   --scope=<SCOPE>        The scope of the resource type.  One of global,
                          node.  This is only valid for BGP peers and is used
                          to indicate whether the peer is a global peer or
                          node-specific.
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
