---
title: calicoctl get
description: Command to list policies in the default output format.
canonical_url: '/reference/calicoctl/get'
---

This sections describes the `calicoctl get` command.

Read the [calicoctl command line interface user reference]({{ site.baseurl }}/reference/calicoctl/overview)
for a full list of calicoctl commands.

> **Note**: The available actions for a specific resource type may be
> limited based on the datastore used for {{site.prodname}} (etcdv3 / Kubernetes API).
> Please refer to the
> [Resources section]({{ site.baseurl }}/reference/resources/overview)
> for details about each resource type.
{: .alert .alert-info}


## Displaying the help text for 'calicoctl get' command

Run `calicoctl get --help` to display the following help menu for the
command.

```
Usage:
  calicoctl get ( (<KIND> [<NAME...>]) |
                --filename=<FILENAME>) [--recursive] [--skip-empty]
                [--output=<OUTPUT>] [--config=<CONFIG>] [--namespace=<NS>] [--all-namespaces]

Examples:
  # List all policy in default output format.
  calicoctl get policy

  # List specific policies in YAML format
  calicoctl get -o yaml policy my-policy-1 my-policy-2


Options:
  -h --help                    Show this screen.
  -f --filename=<FILENAME>     Filename to use to get the resource.  If set to
                               "-" loads from stdin. If filename is a directory, this command is
                               invoked for each .json .yaml and .yml file within that directory,
                               terminating after the first failure.
  -R --recursive               Process the filename specified in -f or --filename recursively.
     --skip-empty              Do not error if any files or directory specified using -f or --filename contain no
                               data.
  -o --output=<OUTPUT FORMAT>  Output format.  One of: yaml, json, ps, wide,
                               custom-columns=..., go-template=...,
                               go-template-file=...   [Default: ps]
  -c --config=<CONFIG>         Path to the file containing connection
                               configuration in YAML or JSON format.
                               [default: /etc/calico/calicoctl.cfg]
  -n --namespace=<NS>          Namespace of the resource.
                               Only applicable to NetworkPolicy and WorkloadEndpoint.
                               Uses the default namespace if not specified.
  -A --all-namespaces          If present, list the requested object(s) across
                               all namespaces.
  --export                     If present, returns the requested object(s) stripped of
                               cluster-specific information. This flag will be ignored
                               if <NAME> is not specified.
  --context=<context>          The name of the kubeconfig context to use.

Description:
  The get command is used to display a set of resources by filename or stdin,
  or by type and identifiers.  JSON and YAML formats are accepted for file and
  stdin format.

  Valid resource types are:


    * bgpConfiguration
    * bgpPeer
    * felixConfiguration
    * globalNetworkPolicy
    * hostEndpoint
    * ipPool
    * networkPolicy
    * networkSet
    * node
    * profile
    * workloadEndpoint

  The resource type is case insensitive and may be pluralized.

  Attempting to get resources that do not exist will simply return no results.

  When getting resources by type, only a single type may be specified at a
  time.  The name and other identifiers (hostname, scope) are optional, and are
  wildcarded when omitted. Thus if you specify no identifiers at all (other
  than type), then all configured resources of the requested type will be
  returned.

  By default the results are output in a ps-style table output.  There are
  alternative ways to display the data using the --output option:

    ps                    Display the results in ps-style output.
    wide                  As per the ps option, but includes more headings.
    custom-columns        As per the ps option, but only display the columns
                          that are requested in the comma-separated list.
    golang-template       Display the results using the specified golang
                          template.  This can be used to filter results, for
                          example to return a specific value.
    golang-template-file  Display the results using the golang template that is
                          contained in the specified file.
    yaml                  Display the results in YAML output format.
    json                  Display the results in JSON output format.

  Note that the data output using YAML or JSON format is always valid to use as
  input to all of the resource management commands (create, apply, replace,
  delete, get).

  Please refer to the docs at https://projectcalico.docs.tigera.io for more details on
  the output formats, including example outputs, resource structure (required
  for the golang template definitions) and the valid column names (required for
  the custom-columns option).
```
{: .no-select-button}

### Options
```
-h --help                    Show this screen.
-f --filename=<FILENAME>     Filename to use to get the resource.  If set to
                             "-" loads from stdin.
-o --output=<OUTPUT FORMAT>  Output format.  One of: yaml, json, ps, wide,
                             custom-columns=..., go-template=...,
                             go-template-file=...   [Default: ps]
-n --namespace=<NS>          Namespace of the resource.
                             Only applicable to NetworkPolicy, NetworkSet, and WorkloadEndpoint.
                             Uses the default namespace if not specified.
-A --all-namespaces          If present, list the requested object(s) across
                             all namespaces.
--export                     If present, returns the requested object(s) stripped of
                             cluster-specific information. This flag will be ignored
                             if the resource name is not specified.
```
{: .no-select-button}

### General options

```
-c --config=<CONFIG>         Path to the file containing connection
                             configuration in YAML or JSON format.
                             [default: /etc/calico/calicoctl.cfg]
```
{: .no-select-button}

### Output options

#### `ps`

This is the default output format.  It displays output in ps-style table output with sufficient columns to
uniquely identify the resource.

The headings displayed for each resource type is fixed.  However, we `wide` option for displaying additional
columns, and `custom-columns` for selecting which columns to display.

Example:
```bash
calicoctl get hostEndpoint
```

Response:
```
NAME          NODE
endpoint1     host1
myhost-eth0   myhost
```
{: .no-select-button}

#### `wide`

Similar to the `ps` format, the `wide` option displays output in ps-style table output but with additional columns.

The headings displayed for each resource type is fixed.  See `custom-columns` for selecting which columns to display.

Example:
```bash
calicoctl get hostEndpoint --output=wide
```

Response:
```
NAME           NODE     INTERFACE   IPS                PROFILES
endpoint1      host1                1.2.3.4,0:bb::aa   prof1,prof2
myhost-eth0    myhost                                  profile1
```
{: .no-select-button}

#### `custom-columns`

Similar to the `ps` format, the `custom-columns` option displays output in ps-style table output but allows the user
to specify and ordered, comma-separated list of columns to display in the output.  The valid heading names for each
resource type is documented in the [Resources]({{ site.baseurl }}/reference/resources/overview) guide.

Example:
```
calicoctl get hostEndpoint --output=custom-columns=NAME,IPS
```

Response:
```
NAME        IPS
endpoint1   1.2.3.4,0:bb::aa
myhost-eth0
```
{: .no-select-button}

#### `yaml / json`

The `yaml` and `json` options display the output as a list of YAML documents or JSON dictionaries.  The fields for
resource type are documented in the [Resources]({{ site.baseurl }}/reference/resources/overview) guide.

The output from either of these formats may be used as input for all of the resource management commands.

Example:
```bash
calicoctl get hostEndpoint --output=yaml
```

Response:
```yaml
- apiVersion: projectcalico.org/v3
  kind: HostEndpoint
  metadata:
    labels:
      type: database
    name: endpoint1
  spec:
    node: host1
    expectedIPs:
    - 1.2.3.4
    - 0:bb::aa
    profiles:
    - prof1
    - prof2
- apiVersion: projectcalico.org/v3
  kind: HostEndpoint
  metadata:
    name: myhost-eth0
  spec:
    node: myhost
    profiles:
    - profile1
```
{: .no-select-button}

#### `go-template / go-template-file`

The `go-template` and `go-template-file` options display the output using a golang template specified as a string
on the CLI, or defined in a separate file.
When writing a template, be aware that the data passed to the template is a golang slice of resource-lists.  The
resource-lists are defined in the [libcalico API]({{ site.baseurl }}/reference/resources/overview) and there is a resource-list defined for
each resource type.  A resource-list contains an Items field which is itself a slice of resources.  Thus, to output
the "Name" field from the supplied data, it is necessary to enumerate over the slice of resource-lists and the items
within that list.

Example:
{% raw %}
```bash
bin/calicoctl get hostEndpoint --output=go-template="{{range .}}{{range .Items}}{{.ObjectMeta.Name}},{{end}}{{end}}"
endpoint1,eth0,
```
{% endraw %}

## See also

-  [Installing calicoctl]({{ site.baseurl }}/maintenance/clis/calicoctl/install).
-  [Resources]({{ site.baseurl }}/reference/resources/overview) for details on all valid resources, including file format
   and schema
-  [NetworkPolicy]({{ site.baseurl }}/reference/resources/networkpolicy) for details on the {{site.prodname}} selector-based policy model
