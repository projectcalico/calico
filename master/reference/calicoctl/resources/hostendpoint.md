---
title: Host Endpoint resource (hostEndpoint)
---

A host endpoint refers to the “bare-metal” interfaces attached to the host that is running Calico’s agent, Felix.  Each endpoint may specify a set of labels and list of profiles that Calico will use to apply policy to the interface.  If no profiles or labels are applied, Calico, by default, will not apply any policy.

### Sample YAML
```
apiVersion: v1
kind: hostEndpoint
metadata:
  name: eth0
  node: myhost
  labels:
    type: production
spec:
  interface: eth0
  expectedIPs: 
  - 192.168.0.1
  - 192.168.0.2
  profiles: 
  - profile1
  - profile2
```

### Definitions
#### Metadata

| name     | description                                               | requirements                             | schema |
|----------|-----------------------------------------------------------|------------------------------------------|--------|
| name     | The name of this hostEndpoint.                            |                                          | string |
| node     | The hostname of the host where this hostEndpoint resides. | Required for `create`/`update`/`apply`/`delete`. | string |
| labels   | A set of labels to apply to this endpoint.                |      | Dictionary with key and values as strings. |

#### Spec

| name         | description                                              | requirements                | schema          |
|--------------|----------------------------------------------------------|-----------------------------|-----------------|
| interfaceName    | The name of the interface to apply policy to.            |                             | string          |
| expectedIPs  | The expected IP addresses associated with the interface. | Valid IPv4 or IPv6 address. | list of strings |
| profiles     | The list of profiles to apply to the endpoint.           |                             | list of strings |
