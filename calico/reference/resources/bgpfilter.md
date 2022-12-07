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
  exportV4:
    - action: accept
      matchOperator: In
      cidr: 77.0.0.0/16
  importV4:
    - action: accept
      matchOperator: NotIn
      cidr: 44.0.0.0/16
  exportV6:
    - action: accept
      matchOperator: Equal
      cidr: 9000::0/64
  importV6:
    - action: accept
      matchOperator: NotEqual
      cidr: 5000::0/64
```

### BGP filter definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema |
|-------------|-----------------------------|-------------------|--------|
| name     | Unique name to describe this resource instance. Must be specified.| Alphanumeric string with optional `.`, `_`, or `-`. | string |

#### Spec

| Field    | Description                                        | Accepted Values                                                                             | Schema                                 | Default    |
|----------|----------------------------------------------------|---------------------------------------------------------------------------------------------|----------------------------------------|------------|
| exportV4 | List of v4 CIDRs and export action (accept/reject) |                                                            | [BGP Filter Rule v4](#bgp-filter-rule-v4) | |
| importV4 | List of v4 CIDRs and import action (accept/reject) |  | [BGP Filter Rule v4](#bgp-filter-rule-v4) | |
| exportV6 | List of v6 CIDRs and export action (accept/reject) |                                                            | [BGP Filter Rule v6](#bgp-filter-rule-v6) | |
| importV6 | List of v6 CIDRs and import action (accept/reject) |  | [BGP Filter Rule v6](#bgp-filter-rule-v6) | |

#### BGP Filter Rule v4


| Field         | Description                               | Accepted Values                   | Schema                                  | Default    |
|---------------|-------------------------------------------|-----------------------------------|-----------------------------------------|------------|
| cidr          | IPv4 range                                | A valid IPv4 CIDR                 | string                                  | |
| matchOperator | Method by which to match candidate routes | `In`, `NotIn`, `Equal`, `NotEqual` | string                                  | |
| action        | Action to be taken for this CIDR          | `Accept` or `Reject`              | string | |

#### BGP Filter Rule v6


| Field         | Description                      | Accepted Values      | Schema                                  | Default    |
|---------------|----------------------------------|----------------------|-----------------------------------------|------------|
| cidr          | IPv6 range                       | A valid IPv6 CIDR    | string                                  | |
| matchOperator | Method by which to match candidate routes | `In`, `NotIn`, `Equal`, `NotEqual` | string                                  | |
| cction        | Action to be taken for this CIDR | `Accept` or `Reject` | string | |

### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| Kubernetes API server | Yes           | Yes    | Yes      |
