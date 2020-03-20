---
title: Profile Resource (Profile)
canonical_url: '/reference/calicoctl/resources/profile'
---

A profile resource (`Profile`) represents a set of rules which are applied
to the individual endpoints to which this profile has been assigned.

Each {{site.prodname}} endpoint or host endpoint can be assigned to zero or more profiles.

Also see the [NetworkPolicy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy) and [GlobalNetworkPolicy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/globalnetworkpolicy) which provide an alternate way to select what policy is applied to an endpoint.

For `calicoctl` [commands]({{site.baseurl}}/{{page.version}}/reference/calicoctl/commands/) that specify a resource type on the CLI, the following
aliases are supported (all case insensitive): `profile`, `profiles`, `pro`, `pros`.

### Sample YAML

The following sample profile allows all traffic from endpoints that
have the profile label set to `profile1` (i.e. endpoints that reference this profile),
except that *all* traffic from 10.0.20.0/24 is denied.

```yaml
apiVersion: projectcalico.org/v3
kind: Profile
metadata:
  name: profile1
spec:
  ingress:
  - action: Deny
    source:
      nets:
      - 10.0.20.0/24
  - action: Allow
    source:
      selector: profile == 'profile1'
  egress:
  - action: Allow
  labelsToApply:
    profile: profile1
```

### Definition

#### Metadata

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| name   | The name of the profile. Required. | Alphanumeric string with optional `.`, `_`, or `-`. | string |
| labels | A set of labels for this profile. |  | map of string key to string values |
| tags (deprecated) | A list of tag names to apply to endpoints using this profile.        | | list of strings |

#### Spec

| Field       | Description                 | Accepted Values   | Schema | Default    |
|-------------|-----------------------------|-------------------|--------|------------|
| ingress  | The ingress rules belonging to this profile. | | List of [Rule](#rule) |
| egress   | The egress rules belonging to this profile. | | List of [Rule](#rule)  |
| labelsToApply | An optional set of labels to apply to each endpoint in this profile (in addition to the endpoint's own labels) |  | map |

#### Rule

{% include {{page.version}}/rule.md %}

#### ICMP

{% include {{page.version}}/icmp.md %}

#### EntityRule

{% include {{page.version}}/entityrule.md %}

#### Selector

{% include {{page.version}}/selectors.md %}

#### Ports

{% include {{page.version}}/ports.md %}


### Supported operations

| Datastore type        | Create/Delete | Update | Get/List | Notes
|-----------------------|---------------|--------|----------|------
| etcdv3                | Yes           | Yes    | Yes      |
| Kubernetes API server | No            | No     | Yes      | {{site.prodname}} profiles are pre-assigned for each Namespace.
