---
title: BGP Filter
description: API for this Calico Enterprise resource.
canonical_url: '/reference/resources/bgpfilter'
---

A BGP filter resource (`BGPFilter`) represents a way to control
routes imported by and exported to BGP peers specified using a
BGP peer resource (`BGPPeer`)

For `kubectl` commands, the following case-sensitive aliases may
be used to specify the resource type on the CLI: `bgpfilters.crd.projectcalico.org`

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: BGPFilter
metadata:
  name: my-filter
spec:
  export_v4:
    - action: accept
      cidr: 77.0.0.0/16
    - action: reject
      cidr: 77.1.0.0/16
  import_v4:
    - action: accept
      cidr: 44.0.0.0/16
    - action: reject
      cidr: 44.1.0.0/16
  export_v6:
    - action: accept
      cidr: 9000::0/64
    - action: reject
      cidr: 9000:1::0/64
  import_v6:
    - action: accept
      cidr: 5000::0/64
    - action: reject
      cidr: 5000:1::0/64
```

### BGP filter definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     | Unique name to describe this resource instance. Must be specified.| Alphanumeric string with optional `.`, `_`, or `-`. | string |

#### Spec

| Field     | Description                                        | Accepted Values                                                                             | Schema                                 | Default    |
|-----------|----------------------------------------------------|---------------------------------------------------------------------------------------------|----------------------------------------|------------|
| export_v4 | List of v4 CIDRs and export action (accept/reject) |                                                            | [BGP Filter Rule v4](#bgpfilterrulev4) | |
| import_v4 | List of v4 CIDRs and import action (accept/reject) |  | [BGP Filter Rule v4](#bgpfilterrulev4) | |
| export_v6 | List of v6 CIDRs and export action (accept/reject) |                                                            | [BGP Filter Rule v6](#bgpfilterrulev6) | |
| import_v6 | List of v6 CIDRs and import action (accept/reject) |  | [BGP Filter Rule v6](#bgpfilterrulev6) | |

#### BGP Filter Rule v4


| Field  | Description                      | Accepted Values   | Schema                                  | Default    |
|--------|----------------------------------|-------------------|-----------------------------------------|------------|
| CIDR   | IPv4 range                       | A valid IPv4 CIDR | string                                  | |
| Action | Action to be taken for this CIDR | `accept` or `reject` | string | |

#### BGP Filter Rule v6


| Field  | Description                      | Accepted Values      | Schema                                  | Default    |
|--------|----------------------------------|----------------------|-----------------------------------------|------------|
| CIDR   | IPv6 range                       | A valid IPv6 CIDR    | string                                  | |
| Action | Action to be taken for this CIDR | `accept` or `reject` | string | |

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| Kubernetes API server | Yes           | Yes    | Yes      |
