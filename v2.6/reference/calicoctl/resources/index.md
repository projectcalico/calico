---
title: Resource Definitions
canonical_url: 'https://docs.projectcalico.org/v3.7/reference/calicoctl/resources/index'
---

This section describes the set of valid resource types that can be managed
through `calicoctl`.  

While resources may be supplied in YAML or JSON format, this guide provides examples in YAML. 

## Overview of resource structure

The calicoctl commands for resource management (create, apply, delete, replace, get)
all take resource manifests as input.  

Each manifest may contain a single resource 
(e.g. a profile resource), or a list of multiple resources (e.g. a profile and two
hostEndpoint resources).

The general structure of a single resource is as follows:

```yaml
apiVersion: v1
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
| apiVersion     | Indicates the version of the API that the data corresponds to. | v1 | string |
| kind     | Specifies the type of resource described by the YAML document. |  | [kind](#supported-kinds) |
| metadata | Contains information used to uniquely identify the particular instance of the resource. | | map |
| spec     | Contains the resource specification. | | map |

### Supported Kinds

The following resources are supported:

- [bgpPeer]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/bgppeer)
- [hostEndpoint]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/hostendpoint)
- [policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy)
- [ipPool]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool)
- [node]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/node)
- [profile]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile)
- [workloadEndpoint]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint)

### Multiple resources in a single file

A file may contain multiple resource documents specified in a YAML list format. For example, the following is the contents of a file containing two `hostEndpoint` resources:

```
- apiVersion: v1
  kind: hostEndpoint
  metadata:
    name: endpoint1
    node: host1
    labels:
      type: database
  spec:
    interface: eth0
    profiles:
    - prof1
    - prof2
    expectedIPs:
    - 1.2.3.4
    - "00:bb::aa"
- apiVersion: v1
  kind: hostEndpoint
  metadata:
    name: endpoint2
    node: host1
    labels:
      type: frontend
  spec:
    interface: eth1
    profiles:
    - prof1
    - prof2
    expectedIPs:
    - 1.2.3.5
```
