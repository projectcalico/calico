---
title: Global domain set
canonical_url: https://docs.projectcalico.org/master/reference/calicoctl/resources/globaldomainset
---

A global domain set resource (GlobalDomainSet) represents an arbitrary set of domain names,
allowing it to be matched by {{site.prodname}} policy.  Domain sets are useful for allowing traffic
to external, non-{{site.prodname}} domains.

The metadata for each domain set includes a set of labels.  When {{site.prodname}} is calculating the set of
IPs that should be allowed for a
[global network policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/globalnetworkpolicy) egress rule, it includes
the IPs for the domain names from any domain sets that match that rule's `domains.selector` field.

For `calicoctl` commands that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `globaldomainset`, `globaldomainsets`.

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: GlobalDomainSet
metadata:
  name: a-name-for-the-set
  labels:
    role: external-database
spec:
  nets:
  - db-prod.my-account.aws.com
  - db-test.my-account.aws.com
```

### Global domain set definition

#### Metadata

| Field       | Description                                  | Accepted Values   | Schema  |
|-------------|----------------------------------------------|-------------------|---------|
| name        | The name of this domain set.                 | Lower-case alphanumeric with optional `-`  | string  |
| labels      | A set of labels to apply to this domain set. |                   | map     |

#### Spec

| Field       | Description                                  | Accepted Values                                         | Schema | Default    |
|-------------|----------------------------------------------|---------------------------------------------------------|--------|------------|
| domains     | The domain names to include in the set.      | Valid DNS domain names                                  | list   |            |
