---
title: Workload Endpoint Resource (WorkloadEndpoint)
canonical_url: 'https://docs.projectcalico.org/v3.2/reference/calicoctl/resources/workloadendpoint'
---

A workload endpoint resource (`WorkloadEndpoint`) represents an interface
connecting a {{site.prodname}} networked container or VM to its host.

Each endpoint may specify a set of labels and list of profiles that {{site.prodname}} will use
to apply policy to the interface.

A workload endpoint is a namespaced resource, that means a
[NetworkPolicy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy)
in a specific namespace only applies to the WorkloadEndpoint in that namespace.
Two resources are in the same namespace if the namespace value is set the same
on both.

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) 
that specify a resource type on the CLI, the following aliases are supported (all case 
insensitive): `workloadendpoint`, `workloadendpoints`, `wep`, `weps`.

> **Note**: While `calicoctl` allows the user to fully manage Workload Endpoint resources,
> the lifecycle of these resources is generally handled by an orchestrator-specific
> plugin such as the {{site.prodname}} CNI plugin, the {{site.prodname}} Docker network plugin,
> or the {{site.prodname}} OpenStack Neutron Driver. In general, we recommend that you only
> use `calicoctl` to view this resource type.
{: .alert .alert-info}


### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: WorkloadEndpoint
metadata:
  name: node1-k8s-my--nginx--b1337a-eth0
  namespace: default
  labels:
    app: frontend
    projectcalico.org/namespace: default
    projectcalico.org/orchestrator: k8s
spec:
  node: node1
  orchestrator: k8s
  endpoint: eth0
  containerID: 1337495556942031415926535
  pod: my-nginx-b1337a
  endpoint: eth0
  interfaceName: cali0ef24ba
  mac: ca:fe:1d:52:bb:e9
  ipNetworks:
  - 192.168.0.0/32
  profiles:
  - profile1
  ports:
  - name: some-port
    port: 1234
    protocol: TCP
  - name: another-port
    port: 5432
    protocol: UDP
```

### Definitions

#### Metadata

| Field     | Description                                                        | Accepted Values                                          | Schema | Default   |
|-----------|--------------------------------------------------------------------|----------------------------------------------------------|--------|-----------|
| name      | The name of this workload endpoint resource. Required.             |  Alphanumeric string with optional `.`, `_`, or `-`      | string |           |
| namespace | Namespace provides an additional qualification to a resource name. |                                                          | string | "default" |
| labels    | A set of labels to apply to this endpoint.                         |                                                          |   map  |           |

#### Spec

| Field          | Description                                                   | Accepted Values | Schema                                 | Default |
|----------------|---------------------------------------------------------------|-----------------|----------------------------------------|---------|
| workload       | The name of the workload to which this endpoint belongs.      |                 | string                                 |
| orchestrator   | The orchestrator that created this endpoint.                  |                 | string                                 |
| node           | The node where this endpoint resides.                         |                 | string                                 |
| containerID    | The CNI CONTAINER_ID of the workload endpoint.                |                 | string                                 |
| pod            | Kubernetes pod name for this woekload endpoint.               |                 | string                                 |
| endpoint       | Container network interface name.                             |                 | string                                 | 
| ipNetworks     | The CIDRs assigned to the interface.                          |                 | List of strings                        |
| ipNATs         | List of 1:1 NAT mappings to apply to the endpoint.            |                 | List of [IPNATs](#ipnat)               |
| ipv4Gateway    | The gateway IPv4 address for traffic from the workload.       |                 | string                                 |
| ipv6Gateway    | The gateway IPv6 address for traffic from the workload.       |                 | string                                 |
| profiles       | List of profiles assigned to this endpoint.                   |                 | List of strings                        |
| interfaceName  | The name of the host-side interface attached to the workload. |                 | string                                 |
| mac            | The source MAC address of traffic generated by the workload.  |                 | IEEE 802 MAC-48, EUI-48, or EUI-64     |
| ports          | List on named ports that this workload exposes.               |                 | List of [EndpointPorts](#endpointport) |


#### IPNAT

{% include {{page.version}}/ipnat.md %}

#### EndpointPort

{% include {{page.version}}/endpointport.md %}

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | No            | Yes    | Yes      | WorkloadEndpoints are directly tied to a Kubernetes pod.
