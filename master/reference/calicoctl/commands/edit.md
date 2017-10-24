---
title: calicoctl edit
---

This sections describes the `calicoctl edit` command.

Read the [calicoctl command line interface user reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) 
for a full list of calicoctl commands.

> The available actions for a specific resource type may be limited based on the datastore
> used for Calico (etcdv2 / Kubernetes API).  Please refer to the [Resources section]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/)
> for details about each resource type.

## Displaying the help text for 'calicoctl edit' command

Run `calicoctl edit --help` to display the following help menu for the 
command.

```
Usage:
  calicoctl edit ([--scope=<SCOPE>] [--node=<NODE>] [--orchestrator=<ORCH>]
                  [--workload=<WORKLOAD>] (<KIND> [<NAME>]) |
                  --filename=<FILENAME>)
                 [--output=<OUTPUT>] [--config=<CONFIG>]

Examples:
  # Edit all policy in YAML format.
  calicoctl edit policy

  # Edit a specific policy in JSON format
  calicoctl edit -o json policy my-policy-1

  # Use an alternative editor
  CALICOCTL_EDITOR="nano" calicoctl edit policy

Options:
  -h --help                    Show this screen.
  -f --filename=<FILENAME>     Filename to use to get the resource.  If set to
                               "-" loads from stdin.
  -o --output=<OUTPUT FORMAT>  Output format.  One of: yaml, json.
                               [Default: yaml]
  -n --node=<NODE>             The node (this may be the hostname of the
                               compute server if your installation does not
                               explicitly set the names of each Calico node).
     --orchestrator=<ORCH>     The orchestrator (valid for workload endpoints).
     --workload=<WORKLOAD>     The workload (valid for workload endpoints).
     --scope=<SCOPE>           The scope of the resource type.  One of global,
                               node.  This is only valid for BGP peers and is
                               used to indicate whether the peer is a global
                               peer or node-specific.
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]

Description:
  The edit command is used to edit a set of resources that have been specified
  on the command line or through the specified file.  JSON and YAML formats are
  accepted for file and stdin format.

  Valid resource types are node, bgpPeer, hostEndpoint, workloadEndpoint,
  ipPool, policy and profile.  The <TYPE> is case insensitive and may be
  pluralized.

  Attempting to edit resources that do not exist is not possible.  Primary
  identifiers for the resources may not be changed in an edit.

  When editing resources by type, only a single type may be specified at a
  time.  The name and other identifiers (hostname, scope) are optional, and are
  wildcarded when omitted. Thus if you specify no identifiers at all (other
  than type), then all configured resources of the requested type will be
  returned.
```

### Options
```
-h --help                    Show this screen.
-f --filename=<FILENAME>     Filename to use to get the resource.  If set to
                             "-" loads from stdin.
-o --output=<OUTPUT FORMAT>  Output format.  One of: yaml, json, ps, wide,
                             custom-columns=..., go-template=...,
                             go-template-file=...   [Default: ps]
-n --node=<NODE>             The node (this may be the hostname of the
                             compute server if your installation does not
                             explicitly set the names of each Calico node).
   --orchestrator=<ORCH>     The orchestrator (valid for workload endpoints).
   --workload=<WORKLOAD>     The workload (valid for workload endpoints).
   --scope=<SCOPE>           The scope of the resource type.  One of global,
                             node.  This is only valid for BGP peers and is
                             used to indicate whether the peer is a global
                             peer or node-specific.
```

### General options

```
-c --config=<CONFIG>         Path to the file containing connection
                             configuration in YAML or JSON format.
                             [default: /etc/calico/calicoctl.cfg]
```

## See also

-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) for details on the Calico selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup) for details on configuring `calicoctl` to access
   the Calico datastore.
