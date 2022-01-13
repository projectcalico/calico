---
title: calicoctl patch
description: Command to update a node with a patch. 
canonical_url: '/reference/calicoctl/patch'
---

This sections describes the `calicoctl patch` command.

Read the [calicoctl command line interface user reference]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl patch' command

Run `calicoctl patch --help` to display the following help menu for the
command.

```
Usage:
  calicoctl patch <KIND> <NAME> --patch=<PATCH> [--type=<TYPE>] [--config=<CONFIG>] [--namespace=<NS>]

Examples:
  # Partially update a node using a strategic merge patch.
  calicoctl patch node node-0 --patch '{"spec":{"bgp": {"routeReflectorClusterID": "CLUSTER_ID"}}}'

  # Partially update a node using a json merge patch.
  calicoctl patch node node-0 --patch '{"spec":{"bgp": {"routeReflectorClusterID": "CLUSTER_ID"}}}' --type json

Options:
  -h --help                  Show this screen.
  -p --patch=<PATCH>         Spec to use to patch the resource.
  -t --type=<TYPE>           Format of patch type:
                                strategic   Strategic merge patch (default)
                                json        JSON Patch, RFC 6902 (not yet implemented)
                                merge       JSON Merge Patch, RFC 7386 (not yet implemented)
  -c --config=<CONFIG>       Path to the file containing connection
                             configuration in YAML or JSON format.
                             [default: ` + constants.DefaultConfigPath + `]
  -n --namespace=<NS>        Namespace of the resource.
                             Only applicable to NetworkPolicy, NetworkSet, and WorkloadEndpoint.
                             Uses the default namespace if not specified.
  --context=<context>        The name of the kubeconfig context to use.

Description:
  The patch command is used to patch a specific resource by type and identifiers in place.
  Currently, only JSON format is accepted.
  
  Valid resource types are:

    * bgpConfiguration
    * bgpPeer
    * felixConfiguration
    * globalNetworkPolicy
    * globalNetworkSet
    * hostEndpoint
    * ipPool
    * networkPolicy
    * networkSet
    * node
    * profile
    * workloadEndpoint

  The resource type is case insensitive and may be pluralized.
  Attempting to patch a resource that does not exists is treated as a
  terminating error unless the --skip-not-exists flag is set.  If this flag is
  set, resources that do not exist are skipped.
  
  When patching resources by type, only a single type may be specified at a
  time.  The name is required along with any and other identifiers required to
  uniquely identify a resource of the specified type.
```
{: .no-select-button}

### Examples

1. Patch an IP Pool to enable outgoing NAT:

   ```bash
   calicoctl patch ippool ippool1 -p '{"spec":{"natOutgoing": true}}'
   ```

   Results indicate that a resource was successfully patched:

   ```
   Successfully patched 1 'ipPool' resource
   ```
   {: .no-select-button}

### Options

```
-p --patch=<PATCH>        Spec to use to patch the resource.
-t --type=<TYPE>          Format of patch type:
                             strategic   Strategic merge patch (default)
                             json        JSON Patch, RFC 6902 (not yet implemented)
                             merge       JSON Merge Patch, RFC 7386 (not yet implemented)
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
