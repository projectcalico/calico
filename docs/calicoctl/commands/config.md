> ![warning](../images/warning.png) This document describes an alpha release of calicoctl
>
> See note at top of [calicoctl guide](../README.md) main page.

# User reference for 'calicoctl config' commands

This sections describes the `calicoctl config` commands.

Read the [calicoctl command line interface user reference](../calicoctl.md) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl config' commands

Run `calicoctl create --help` to display the following help menu for the 
calicoctl create command.

```
Set the ETCD server access information in the environment variables
or supply details in a config file.

Manage system configuration parameters.

Usage:
  calicoctl config set <NAME> <VALUE>
      [--scope=<SCOPE>] [--component=<COMPONENT>] [--hostname=<HOSTNAME>] [--config=<CONFIG>]
  calicoctl config unset <NAME>
      [--scope=<SCOPE>] [--component=<COMPONENT>] [--hostname=<HOSTNAME>] [--config=<CONFIG>]
  calicoctl config view [<NAME>]
      [--scope=<SCOPE>] [--component=<COMPONENT>] [--hostname=<HOSTNAME>] [--config=<CONFIG>]

These commands can be used to manage system level configuration.  The table below details the
valid config names and values, and for each specifies the valid scope and component.  The scope
indicates whether the config applies at a global or node-specific scope.  The component indicates
a specific component in the Calico architecture.  If a config option is only valid for a single
scope then the scope need not be explicitly specified in the command; similarly for the component
option.  If the scope is set to 'node' then the hostname must be specified for the set and unset
commands.

The unset command reverts configuration back to its initial value.  Depending on the configuration
option, this either deletes the configuration completely from the datastore, or resets it to the
original system default value.

 Name                | Component | Scope       | Value                                  | Unset value
---------------------+-----------+-------------+----------------------------------------+-------------
 logLevel            | bgp       | global,node | none,debug,info                        | -
                     | felix     | global,node | none,debug,info,warning,error,critical | -
 nodeToNodeMesh      | bgp       | global      | on,off                                 | on
 defaultNodeASNumber | bgp       | global      | 0-4294967295                           | 64511
 ipip                | felix     | global      | on,off                                 | -

Examples:
  # Turn off the full BGP node-to-node mesh
  calicoctl config set nodeToNodeMesh off

  # Set BGP log level to info for node with hostname "host1"
  calicoctl config set logLevel info --scope=node --component=bgp --hostname=host1

  # Display the full set of config values
  calicoctl config view

Options:
  -n --hostname=<HOSTNAME>     The hostname.
  --scope=<SCOPE>              The scope of the resource type.  One of global, node.
  --component=<COMPONENT>      The component.  One of bgp, felix.
  -c --config=<CONFIG>         Filename containing connection configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
```

## Command description
The calicoctl config commands are used to manage system level configuration options.
The following sections describe each sub-command.

See [Configuration Options](#configuration-options) below for a brief description of each
configuration option.

### `calicoctl config set`
This command sets an individual configuration parameter to the specified value.

If the configuration option is valid over multiple scopes (global or node) then it is necessary
to explicitly include the `--scope` option.  Similarly, if the configuration option is valid in multiple
components (BGP or Felix) then it is necessary to explicitly include the `--component` option.
For example:
-  the  `ipip` option is only valid for the the global scope and the felix component, therefore it is
   not necessary to include the `--scope` nor the `--component` options
-  the `logLevel` is valid for global and node scope, and for the Felix and BGP components, therefore it
   is necessary to include *both* the `--scope` and `--component` options.

#### Examples

```
# Set the default AS number to use for each Calico node to be 65551.
$ calicoctl config set defaultNodeASNumber 65551

# Set the default logging level for Felix to info
$ calicoctl config set logLevel info --scope=global --component=felix

# Set the logging level for Felix on node "host1" instances to warning
$ calicoctl config set logLevel warning --scope=node --component=felix --hostname=host1
```

### `calicoctl config unset`
This command unsets an individual configuration parameter.  This returns it to the original system
default.  In some cases this will remove the configuration entirely, and in others will re-apply the original
default value.

See note in `calicoctl config set` help for information on the `--scope` and  `--component` options.

#### Examples

```
# Unset the default logging level for Felix (reverts to default level)
$ calicoctl config unset logLevel info --scope=global
```

### `calicoctl config view`
This command displays the current system configuration that matches the supplied <NAME>, <SCOPE>, <COMPONENT> and
<HOSTNAME>.  These parameters are all optional, and when not specified can be regarded as wildcarded values. For 
example:
-  specifying no option values will show all of the stored system config
-  specifying just a scope of global will display all of the config that operates at a global scope.

#### Examples

```
# View all configuration parameters that have been set
$ calicoctl config view
COMPONENT   SCOPE    HOSTNAME   NAME                  VALUE        
bgp         global              defaultNodeASNumber   4294967295   
bgp         global              nodeToNodeMesh        on           
bgp         node     Node1      logLevel              info       
felix       global              ipip                  off          

# View all configuration parameters of global scope that have been set
$ calicoctl config view --scope=global
COMPONENT   SCOPE    HOSTNAME   NAME                  VALUE        
bgp         global              defaultNodeASNumber   4294967295   
bgp         global              nodeToNodeMesh        on           
felix       global              ipip                  off          

# View all logLevel parameters.
$ calicoctl config view logLevel
COMPONENT   SCOPE    HOSTNAME   NAME                  VALUE        
bgp         node     Node1      logLevel              info       
```

## Details for all `calicoctl config` sub-commands

### Configuration Options

#### `logLevel`
This sets the internal logging level in a specific Calico component.

-  If set at a global scope then this sets the component logging level across all nodes.
-  If set at a node scope then this sets the component logging level on an individual node.  This
   overrides any value set at a global scope.

#### `nodeToNodeMesh`
This is used to specify whether the full automatic BGP node-to-node mesh is turned on or off.

-  When set to `on` (the default), Calico will automatically create a full BGP peering mesh between
   all Calico nodes in the cluster.
   it may be more suitable to use a Route Reflector for improved scaling.
-  When set to `off`, Calico will not create a full BGP peering mesh between all Calico nodes in the
   cluster.  For larger deployments using a Route Reflector, or for more complicated peering
   arrangements this should be set to `off` and explicit BGP peers configured.

#### `defaultNodeASNumber`
This is used to specify the AS number to use by default if it is not explicitly specified when 
starting the Calico node container image.

#### `ipip`
This is used to turn IP-in-IP functionality on or off at a global level in the Felix routing
component.

If you require IP-in-IP for your deployment, it is necessary to enable IP-in-IP globally using
this configuration option, *and* to enable IP-in-IP on pools that will be used for IP allocation
on the workloads requiring IP-in-IP connectivity.

### Options
```
  -n --hostname=<HOSTNAME>     The hostname.
  --scope=<SCOPE>              The scope of the resource type.  One of global, node.
  --component=<COMPONENT>      The component.  One of bgp, felix.
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

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico-go/docs/calicoctl/commands/config.md?pixel)](https://github.com/igrigorik/ga-beacon)
