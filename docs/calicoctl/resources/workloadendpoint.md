# Host Endpoints Resource
Workload endpoints refer to the host-facing side of the Container's veth pair. Each endpoint may specify a set of labels and list of profiles that Calico will use to apply policy to the interface.  If no profiles or labels are applied, Calico, by default, will not apply any policy.

### Sample YAML
```
apiVersion: v1
kind: workloadEndpoint
metadata:
  name: cali0ef24ba
  workloadID:
  orchestratorID: cni
  hostname: rack1-host1
  labels:
    tier: production
spec:
  ipNetworks:
  - 192.168.0.0/16
  profiles:
  - profile1
  - profile2
  interfaceName: cali0ef24ba
  mac: 01:23:45:67:89:ab:cd:ef
```

### Definitions
#### Metadata
| name           | description                                                | requirements                             | schema |
|----------------|------------------------------------------------------------|------------------------------------------|--------|
| name           | The name of this endpoint resource.                        | Required for `create`/`update`/`delete`. | string |
| workloadID     | The unique ID of the workload this endpoint belongs to.    | Required for `create`/`update`/`delete`. | string |
| orchestratorID | The ID of the orchestrator that created this endpoint.     | Required for `create`/`update`/`delete`. | string |
| hostname       | The hostname of the host where this endpoint resides.      | Required for `create`/`update`/`delete`. | string |
| labels         | A set of labels to apply to this endpoint.                 |      | Dictionary with key and values as strings. |

#### Spec
| name          | description                                             | requirements                | schema          |
|---------------|---------------------------------------------------------|-----------------------------|-----------------|
| ipNetworks    | The CIDRS assigned to the interface. | | List of strings |
| profiles      | List of profiles assigned to this endpoint. |                          | List of strings |
| interfaceName | The name of the interface on the host that this endpoint represents. | | List of strings |
| mac           | The MAC address assigned to this endpoint. | | byte string, following [golang mac format](https://golang.org/pkg/net/#ParseMAC) |
