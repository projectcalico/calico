---
title: Multiple Regions
canonical_url: 'https://docs.projectcalico.org/v3.5/usage/openstack/multiple-regions'
---

If you use a [multiple region
deployment](https://docs.openstack.org/kolla-ansible/rocky/user/multi-regions.html)
of OpenStack, you can use {{site.prodname}} to facilitate defining security
policy between VMs in different regions.

## Architecture

The way this works is that all of the regions share the same {{site.prodname}}
etcd datastore, but each region uses a different {{site.prodname}} namespace.
For example, when the Neutron server for region "xyz-east" generates
{{site.prodname}}
[WorkloadEndpoint]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint)
and
[NetworkPolicy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/networkpolicy)
data automatically from OpenStack VMs and security groups, it writes that into
the {{site.prodname}} datastore in the namespace "openstack-region-xyz-east".

Because all the information is in the same {{site.prodname}} datastore, you can
then define {{site.prodname}} policy for communication between VMs in different
regions.

> **Note**: There isn't currently any simple way to define policy between
> different regions using only the OpenStack API.  When a security group
> specifies a set of remote peers (i.e. that are allowed to send or prevented
> from sending a kind of traffic) it can do that either as an IP prefix or as a
> 'remote' security group ID, meaning the VMs that belong to that security
> group.  But a 'remote' security group ID has to be in the same region as
> where the overall security group is being defined, and can only identify VMs
> within that same region.  {: .alert .alert-info}

## Installation

To install a multi-region OpenStack deployment with Calico, proceed
region-by-region and follow [the normal procedure for adding Calico to an
OpenStack
region]({{site.baseurl}}/{{page.version}}/getting-started/openstack/installation),
except for these points:

1.  Only install a single etcd database (instead of one per region) and
    configure all of the regions to use that as their {{site.prodname}}
    datastore.

1.  In `/etc/calico/felix.cfg` on each compute host, add

    ```
    [global]
    OpenstackRegion = <region>
    ```

    where `<region>` is the name of the region that that compute host belongs to.

1.  In `/etc/neutron/neutron.conf` on each controller and compute node, add

    ```
    [calico]
    openstack_region = <region>
    ```

    where `<region>` is the name of the region that that node belongs to.

## Configuring cross-region policy

Suppose that:

- you have two regions, "RegionOne" and "RegionTwo"

- you have a set of VMs in RegionOne belonging to security group
  a7734e61-b545-452d-a3cd-0189cbd9747a

- you have a set of VMs in RegionTwo belonging to security group
  85cc3048-abc3-43cc-89b3-377341426ac5

- you want to allow the VMs in RegionTwo to connect to port 80 of the VMs in
  RegionOne.

You could do that by configuring this {{site.prodname}} policy:

```yaml
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-tcp-80
  namespace: openstack-region-RegionOne
spec:
  selector: "has(sg.projectcalico.org/openstack-a7734e61-b545-452d-a3cd-0189cbd9747a)"
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: TCP
    source:
      namespaceSelector: "all()"
      selector: "has(sg.projectcalico.org/openstack-85cc3048-abc3-43cc-89b3-377341426ac5)"
    destination:
      ports:
      - 80
```

In words, this says that connections to port 80 of the VMs with the label for
the a7734e61... security group are allowed from VMs - in any namespace - with
the label for the 85cc3048... security group.  We know that the 85cc3048... VMs
_are_ in a different namespace from the a7734e61... VMs, so the
`namespaceSelector: "all()"` here - which allows the connecting VMs to come
from any region or namespace - is critical for this policy to work as intended.

You can use any of the
[labels]({{site.baseurl}}/{{page.version}}/usage/openstack/labels) that
{{site.prodname}} adds to OpenStack VM endpoints, to identify a set of allowed
(or denied) clients.  You can also use `nets` or `notNets` instead of
`selector`, to identify clients by IP address.
