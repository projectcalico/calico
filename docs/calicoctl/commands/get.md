# User reference for 'calicoctl get' commands

This sections describes the `calicoctl get` command.

Read the [calicoctl command line interface user reference](../calicoctl.md) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl get' command

Run `calicoctl get --help` to display the following help menu for the 
calicoctl get command.

```
Set the ETCD server access information in the environment variables
or supply details in a config file.

Display one or many resources identified by file, stdin or resource type and name.

Valid resource kinds are bgpPeer, hostEndpoint, policy, pool and profile.  The <KIND>
parameter is case insensitive and may be pluralized.

By specifying the output as 'go-template' and providing a Go template as the value
of the --go-template flag, you can filter the attributes of the fetched resource(s).

Usage:
  calicoctl get ([--hostname=<HOSTNAME>] [--scope=<SCOPE>] (<KIND> [<NAME>]) |
                 --filename=<FILENAME>)
                [--output=<OUTPUT>] [--config=<CONFIG>]


Examples:
  # List all policy in default output format.
  calicoctl get policy

  # List a specific policy in YAML format
  calicoctl get -o yaml policy my-policy-1

Options:
  -f --filename=<FILENAME>     Filename to use to get the resource.  If set to "-" loads from stdin.
  -o --output=<OUTPUT FORMAT>  Output format.  One of: ps, wide, custom-columns=..., yaml, json,
                               go-template=..., go-template-file=...   [Default: ps]
  -n --hostname=<HOSTNAME>     The hostname.
  --scope=<SCOPE>              The scope of the resource type.  One of global, node.  This is only valid
                               for BGP peers and is used to indicate whether the peer is a global peer
                               or node-specific.
  -c --config=<CONFIG>         Filename containing connection configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
```

## calicoctl get

The get command is used to display a set of resources by filename or stdin, or
by type and identifiers.  JSON and YAML formats are accepted for file and stdin format.

Attempting to get resources that do not exist will simply return no results.

When getting resources by type, only a single type may be specified at a time.  The name
and other identifiers (hostname, scope) are optional, and are wildcarded when omitted.
Thus if you specify no identifiers at all (other than type), then all configured resources of
the requested type will be returned.

Possible resource types are bgppeer, hostendpoint, policy, pool and profile.  The <TYPE> is
case insensitive and may be pluralized.

By default the results are output in a ps-style table output.  There are alternative ways to display
the data - which are described below.  Note that the data output using YAML or JSON format may be used
as input to all the resource management commands (create, apply, replace, delete, get).

### Options
```
  -f --filename=<FILENAME>     Filename to use to delete the resource.  If set to "-" loads from stdin.
  -o --output=<OUTPUT FORMAT>  Output format.  One of: ps, wide, custom-columns=..., yaml, json,
                               go-template=..., go-template-file=...   [Default: ps]
     --scope=<SCOPE>           The scope of the resource type.  One of global, node.  This is required
                               for BGP peers and is used to indicate whether the scope of the peer 
                               resource is a global or node-specific.
  -n --hostname=<HOSTNAME>     The hostname.  This is required when deleting 'hostEndpoint' resources, 
                               and 'bgpPeer' resources with scope 'node'.
```

### General options
```
  -c --config=<CONFIG>         Filename containing connection configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
```

### Output options

#### `ps`
This is the default output format.  It displays output in ps-style table output with sufficient columns to
uniquely identify the resource.

The headings displayed for each resource type is fixed.  However, wee `wide` option for displaying additional
columns, and `custom-columns` for selecting which columns to display.

Example
```
$ calicoctl get hostEndpoint
HOSTNAME   NAME        
host1      endpoint1   
myhost     eth0        
```

#### `wide`
Similar to the `ps` format, the `wide` option displays output in ps-style table output but with additional columns.

The headings displayed for each resource type is fixed.  See `custom-columns` for selecting which columns to display.

Example
```
$ calicoctl get hostEndpoint --output=wide
HOSTNAME   NAME        INTERFACE   IPS                PROFILES      
host1      endpoint1               1.2.3.4,0:bb::aa   prof1,prof2   
myhost     eth0                                       profile1      
```

#### `custom-columns`
Similar to the `ps` format, the `custom-columns` option displays output in ps-style table output but allows the user
to specify and ordered, comma-separated list of columns to display in the output.  The valid heading names for each
resource type is documented in the [Resources](../resources/README.md) guide.

Example
```
$ calicoctl get hostEndpoint --output=custom-columns=NAME,IPS
NAME        IPS                
endpoint1   1.2.3.4,0:bb::aa   
eth0                           
```

#### `yaml` and `json`
The `yaml` and `json` options display the output as a list of YAML documents or JSON dictionaries.  The fields for
resource type are documented in the [Resources](../resources/README.md) guide, or alternatively view the structure
definitions (implemented in golang) in the [libcalic API](https://github.com/projectcalico/libcalico-go/tree/master/lib/api).

The output from either of these formats may be used as input for all of the resource management commands.

Example
```
$ calicoctl get hostEndpoint --output=yaml
- apiVersion: v1
  kind: hostEndpoint
  metadata:
    hostname: host1
    labels:
      type: database
    name: endpoint1
  spec:
    expectedIPs:
    - 1.2.3.4
    - 0:bb::aa
    profiles:
    - prof1
    - prof2
- apiVersion: v1
  kind: hostEndpoint
  metadata:
    hostname: myhost
    name: eth0
  spec:
    profiles:
    - profile1
```

#### `go-template` and `go-template-file`
The `go-template` and `go-template-file` options display the output using a golang template specified as a string
on the CLI, or defined in a separate file.

When writing a template, be aware that the data passed to the template is a golang slice of resource-lists.  The 
resource-lists are defined in the [libcalic API](../resources/README.md) and
there is a resource-list defined for each resource type.  A resource-list contains an Items field which is itself
a slice of resources.  Thus, to output the "Name" field from the supplied data, it is necessary to enumerate over
the slice of resource-lists and the items within that list.

Example
```
$ bin/calicoctl get hostEndpoint --output=go-template="{{range .}}{{range .Items}}{{.Metadata.Name}},{{end}}{{end}}"
endpoint1,eth0,
```

### See also
-  [Resources](../resources/README.md) for details on all valid resources, including file format
   and schema
-  [Policy](../resources/policy.md) for details on the Calico selector-based policy model
-  [calicoctl configuration](../general/config.md) for details on configuring `calicoctl` to access
   the Calico datastore.

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico-go/docs/calicoctl/commands/get.md?pixel)](https://github.com/igrigorik/ga-beacon)
