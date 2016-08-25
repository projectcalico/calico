> ![warning](../../images/warning.png) This document describes an alpha release of calicoctl
>
> See note at top of [calicoctl guide](../../README.md) main page.

# Calico resources

This guide describes the set of valid resource types that can be managed
through `calicoctl`. 


## Overview of resource YAML file structure
The calicoctl commands for resource management (create, delete, replace, get) 
all take YAML files as input.  The YAML file may contain a single resource type
(e.g. a profile resource), or a list of multiple resource types (e.g. a profile and two
hostEndpoint resources).

### A single resource
The general structure of a single resource is as follows:

```
apiVersion: v1
kind: <type of resource>
metadata:
  name: <name of resource>
  ... other identifiers required to uniquely identify the resource
  ... labels (when appropriate for the resource type)
spec:
  ... configuration for the resource
```

The `apiVersion` indicates that the version of the API that the data corresponds to is v1
(currently the only version supported).
 
The `kind` specifies the type of resource described by the YAML document.

The `metadata` contains sub-fields which are used identify the particular instance of the
resource.

The `spec` contains the resource specification, i.e. the configuration for the resource.

### Multiple resources in a single file
A file may contain multiple resource documents specified in a YAML list format.

For example, the following is the contents of a file containing two `hostEndpoint` resources.
```
- apiVersion: v1
  kind: hostEndpoint
  metadata:
    name: endpoint1
    hostname: host1
    labels:
      type: database
  spec:
    interface: eth0
    profiles: [prof1, prof2]
    expectedIPs: [1.2.3.4, "00:bb::aa"]
- apiVersion: v1
  kind: hostEndpoint
  metadata:
    name: endpoint2
    hostname: host1
    labels:
      type: frontend
  spec:
    interface: eth1
    profiles: [prof1, prof2]
    expectedIPs: [1.2.3.5]
```

### Required information for calicoctl management commands

#### `calicoctl apply/create/replace`


#### `calicoctl get`


#### `calicoctl delete`



Type
Brief description
profile
Profile objects can be thought of as describing the properties of an endpoint (virtual interface, or bare metal interface).  Each endpoint can reference zero or more profiles.  A profile encapsulates a specific set of tags, labels and ACL rules that are directly applied to the endpoint.  Depending on the use case, profiles may be sufficient to express all policy.
policy
Policy objects can be thought of as being applied to a set of endpoints (rather than being a property of the endpoint) to give more flexible policy arrangements.
Each policy has a label/tag based selector predicate, such as “type == ‘webserver’ && role == ‘frontend’”, that selects which endpoints it should apply to, and an ordering number that specifies the policy’s priority. For each endpoint, Calico applies the security policies that apply to it, in priority order, and then that endpoint’s security profiles.
A host endpoints refer to the “bare-metal” interfaces attached to the host that is running Calico’s agent, Felix.  Each endpoint may specify a set of labels and list of profiles that Calico will use to apply policy to the interface.  If no profiles or labels are applied, Calico, by default, will not apply any policy.



[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/libcalico-go/docs/calicoctl/resources/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
