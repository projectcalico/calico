---
title: Calico resource types
---

This guide describes the set of valid resource types that can be managed
through `calicoctl`.  Data may be supplied in YAML or JSON format for each
resource type, and this guide provides examples in YAML format which may be
translated diretly to JSON using standard YAML to JSON conversion.

## Overview of resource YAML file structure

The calicoctl commands for resource management (create, apply, delete, replace, get)
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

### Definitions

| name     | description                                               | requirements                                                                     | schema |
|----------|-----------------------------------------------------------|----------------------------------------------------------------------------------|--------|
| apiVersion     | Indicates the version of the API that the data corresponds to.                           | Currently only `v1` is accepted. | string |
| kind    | Specifies the type of resource described by the YAML document. | Can be [`bgppeer`]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/bgppeer), [`hostendpoint`]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/hostendpoint), [`policy`]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy), [`IPPool`]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool), [`profile`]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile), or [`workloadendpoint`]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint) | string |
| metadata | Contains sub-fields which are used to uniquely identify the particular instance of the resource. | | YAML |
| spec | Contains the resource specification, i.e. the configuration for the resource. | | YAML |

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
