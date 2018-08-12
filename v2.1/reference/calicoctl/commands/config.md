---
title: calicoctl config
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v2.6/reference/calicoctl/commands/config'
---

This sections describes the `calicoctl config` commands.

The `calicoctl config` command allows users to view or modify
low-level component configurations for Felix and BGP.

Read the [calicoctl Overview]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl config' commands

Run `calicoctl config --help` to display the following help menu for the
commands.

```
Usage:
  calicoctl config set <NAME> <VALUE> [--node=<NODE>]
                                      [--raw=(bgp|felix)]
                                      [--config=<CONFIG>]
  calicoctl config unset <NAME> [--node=<NODE>]
                                [--raw=(bgp|felix)]
                                [--config=<CONFIG>]
  calicoctl config get <NAME> [--node=<NODE>]
                              [--raw=(bgp|felix)]
                              [--config=<CONFIG>]

Examples:
  # Turn off the full BGP node-to-node mesh
  calicoctl config set nodeToNodeMesh off

  # Set global log level to warning
  calicoctl config set logLevel warning

  # Set log level to info for node "node1"
  calicoctl config set logLevel info --node=node1

  # Display the current setting for the nodeToNodeMesh
  calicoctl config get nodeToNodeMesh

Options:
  -n --node=<NODE>      The node name.
     --raw=(bgp|felix)  Apply raw configuration for the specified component.
                        This option should be used with care; the data is not
                        validated and it is possible to configure or remove
                        data that may prevent the component from working as
                        expected.
  -c --config=<CONFIG>  Path to the file containing connection configuration in
                        YAML or JSON format.
                        [default: /etc/calico/calicoctl.cfg]

Description:

These commands can be used to manage global system-wide configuration and some
node-specific low level configuration.

The --node option is used to specify the node name for low-level configuration
that is specific to a particular node.

For configuration that has both global values and node-specific values, the
--node parameter is optional:  including the parameter will manage the
node-specific value,  excluding it will manage the global value.  For these
options, if the node-specific value is unset, the global value will be used on
the node.

For configuration that is only global, the --node option should not be
included.  Unsetting the global value will return it to it's original default.

For configuration that is node-specific only, the --node option should be
included.  Unsetting the node value will remove the configuration, and for
supported configuration will then inherit the value from the global settings.

The table below details the valid config options.

 Name            | Scope       | Value                                  |
-----------------+-------------+----------------------------------------+
 logLevel        | global,node | none,debug,info,warning,error,critical |
 nodeToNodeMesh  | global      | on,off                                 |
 asNumber        | global      | 0-4294967295                           |
 ipip            | global      | on,off                                 |
```

### Examples

```
# Turn off the full BGP node-to-node mesh
$calicoctl config set nodeToNodeMesh off

# Set global log level to warning
$calicoctl config set logLevel warning

# Set log level to info for node "node1"
$calicoctl config set logLevel info --node=node1

# Display the current setting for the nodeToNodeMesh
$calicoctl config get nodeToNodeMesh
off
```

### Options

```
-n --node=<NODE>      The node name.
   --raw=(bgp|felix)  Apply raw configuration for the specified component.
                      This option should be used with care; the data is not
                      validated and it is possible to configure or remove
                      data that may prevent the component from working as
                      expected.
```

### General options

```
-c --config=<CONFIG>  Path to the file containing connection
                      configuration in YAML or JSON format.
                      [default: /etc/calico/calicoctl.cfg]
```

## See also

-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) for details on the Calico selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup) for details on configuring `calicoctl` to access
   the Calico datastore.
