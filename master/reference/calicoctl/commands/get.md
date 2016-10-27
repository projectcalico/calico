---
title: calicoctl get
---

This sections describes the `calicoctl get` command.

Read the [calicoctl command line interface user reference]({{site.baseurl}}/{{page.version}}/reference/calicoctl/) 
for a full list of calicoctl commands.

## Displaying the help text for 'calicoctl get' command

Run `calicoctl get --help` to display the following help menu for the 
calicoctl get command.

```
Usage:
  calicoctl get ([--node=<NODE>] [--orchestrator=<ORCH>] [--workload=<WORKLOAD>] [--scope=<SCOPE>]
                 (<KIND> [<NAME>]) |
                 --filename=<FILENAME>)
                [--output=<OUTPUT>] [--config=<CONFIG>]

Examples:
  # List all policy in default output format.
  calicoctl get policy

  # List a specific policy in YAML format
  calicoctl get -o yaml policy my-policy-1

Options:
  -h --help                    Show this screen.
  -f --filename=<FILENAME>     Filename to use to get the resource.  If set to "-" loads from stdin.
  -o --output=<OUTPUT FORMAT>  Output format.  One of: ps, wide, custom-columns=..., yaml, json,
                               go-template=..., go-template-file=...   [Default: ps]
  -n --node=<NODE>             The node (this may be the hostname of the compute server if your
                               installation does not explicitly set the names of each Calico node).
     --orchestrator=<ORCH>     The orchestrator (only used for workload endpoints).
     --workload=<WORKLOAD>     The workload (only used for workload endpoints).
  --scope=<SCOPE>              The scope of the resource type.  One of global, node.  This is only valid
                               for BGP peers and is used to indicate whether the peer is a global peer
                               or node-specific.
  -c --config=<CONFIG>         Filename containing connection configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]

Description:
  The get command is used to display a set of resources by filename or stdin, or by type and
  identifiers.  JSON and YAML formats are accepted for file and stdin format.

  Valid resource types are node, bgpPeer, hostEndpoint, workloadEndpoint, policy, pool and
  profile.  The <TYPE> is case insensitive and may be pluralized.

  Attempting to get resources that do not exist will simply return no results.

  When getting resources by type, only a single type may be specified at a time.  The name
  and other identifiers (hostname, scope) are optional, and are wildcarded when omitted.
  Thus if you specify no identifiers at all (other than type), then all configured resources of
  the requested type will be returned.

  By default the results are output in a ps-style table output.  There are alternative ways to
  display the data using the --output option:
    ps                    Display the results in ps-style output.
    wide                  As per the ps option, but includes more headings.
    custom-columns        As per the ps option, but only display the columns that are requested
                          in the comma serarated list.
    golang-template       Display the results using the specified golang template.  This can be
                          used to filter results to, say, return a specific value.
    golang-template-file  Display the results using the golang template that is contained in the
                          specified file.
    yaml                  Display the results in YAML output format.
    json                  Display the results in JSON output format.

  Note that the data output using YAML or JSON format is always valid to use as input to all of the
  resource management commands (create, apply, replace, delete, get).

  Please refer to the docs at http://docs.projectcalico.org for more details on the output formats,
  including example outputs, resource structure (required for the golang template definitions) and
  the valid column names (required for the custom-columns option).
```

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
resource type is documented in the [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) guide.

Example
```
$ calicoctl get hostEndpoint --output=custom-columns=NAME,IPS
NAME        IPS                
endpoint1   1.2.3.4,0:bb::aa   
eth0                           
```

#### `yaml` and `json`
The `yaml` and `json` options display the output as a list of YAML documents or JSON dictionaries.  The fields for
resource type are documented in the [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) guide, or alternatively view the structure
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
resource-lists are defined in the [libcalico API]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) and there is a resource-list defined for
each resource type.  A resource-list contains an Items field which is itself a slice of resources.  Thus, to output
the "Name" field from the supplied data, it is necessary to enumerate over the slice of resource-lists and the items
within that list.

Example
{% raw %}
```
$ bin/calicoctl get hostEndpoint --output=go-template="{{range .}}{{range .Items}}{{.Metadata.Name}},{{end}}{{end}}"
endpoint1,eth0,
```
{% endraw %}

## See also
-  [Resources]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/) for details on all valid resources, including file format
   and schema
-  [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) for details on the Calico selector-based policy model
-  [calicoctl configuration]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/config) for details on configuring `calicoctl` to access
   the Calico datastore.
