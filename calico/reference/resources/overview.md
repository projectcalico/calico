---
title: Resource definitions
description: Calico resources (APIs) that you can manage using calicoctl.
canonical_url: '/reference/resources/index'
---

This section describes the set of valid resource types that can be managed
through `calicoctl` or `kubectl`.

While resources may be supplied in YAML or JSON format, this guide provides examples in YAML.

## Overview of resource structure

The calicoctl commands for resource management (create, apply, delete, replace, get)
all take resource manifests as input.  

Each manifest may contain a single resource
(e.g. a profile resource), or a list of multiple resources (e.g. a profile and two
hostEndpoint resources).

The general structure of a single resource is as follows:

```yaml
apiVersion: projectcalico.org/v3
kind: <type of resource>
metadata:
  # Identifying information
  name: <name of resource>
  ...
spec:
  # Specification of the resource
  ...
```

### Schema

| Field    | Description           | Accepted Values              | Schema |
|----------|-----------------------|------------------------------|--------|
| apiVersion     | Indicates the version of the API that the data corresponds to. | projectcalico.org/v3 | string |
| kind     | Specifies the type of resource described by the YAML document. |  | [kind](#supported-kinds) |
| metadata | Contains information used to uniquely identify the particular instance of the resource. | | map |
| spec     | Contains the resource specification. | | map |

### Supported kinds

The following resources are supported:

- [BGPConfiguration]({{ site.baseurl }}/reference/resources/bgpconfig)
- [BGPPeer]({{ site.baseurl }}/reference/resources/bgppeer)
- [FelixConfiguration]({{ site.baseurl }}/reference/resources/felixconfig)
- [GlobalNetworkPolicy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy)
- [GlobalNetworkSet]({{ site.baseurl }}/reference/resources/globalnetworkset)
- [HostEndpoint]({{ site.baseurl }}/reference/resources/hostendpoint)
- [IPPool]({{ site.baseurl }}/reference/resources/ippool)
- [NetworkPolicy]({{ site.baseurl }}/reference/resources/networkpolicy)
- [NetworkSet]({{ site.baseurl }}/reference/resources/networkset)
- [Node]({{ site.baseurl }}/reference/resources/node)
- [Profile]({{ site.baseurl }}/reference/resources/profile)
- [WorkloadEndpoint]({{ site.baseurl }}/reference/resources/workloadendpoint)

### Resource name requirements

Every resource must have the `name` field specified. Name must be unique within a namespace.
Name required when creating resources, and cannot be updated.
A valid resource name can have alphanumeric characters with optional `.`, `_`, or `-`. of up to 128 characters total.

### Multiple resources in a single file

A file may contain multiple resource documents specified in a YAML list format. For example, the following is the contents of a file containing two `HostEndpoint` resources:

```
- apiVersion: projectcalico.org/v3
  kind: HostEndpoint
  metadata:
    name: endpoint1
    labels:
      type: database
  spec:
    interface: eth0
    node: host1
    profiles:
    - prof1
    - prof2
    expectedIPs:
    - 1.2.3.4
    - "00:bb::aa"
- apiVersion: projectcalico.org/v3
  kind: HostEndpoint
  metadata:
    name: endpoint2
    labels:
      type: frontend
  spec:
    interface: eth1
    node: host1
    profiles:
    - prof1
    - prof2
    expectedIPs:
    - 1.2.3.5
```
