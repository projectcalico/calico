---
title: Multiple regions
description: Install a multi-region OpenStack deployment with Calico.
canonical_url: '/networking/openstack/multiple-regions'
---

If you use a {% include open-new-window.html text='multiple region
deployment' url='https://docs.openstack.org/kolla-ansible/rocky/user/multi-regions.html' %}
of OpenStack, you can use {{site.prodname}} to facilitate defining security
policy between VMs in different regions.

## Architecture

The way this works is that all of the regions share the same {{site.prodname}}
etcd datastore, but each region uses a different {{site.prodname}} namespace.
For example, when the Neutron server for region "xyz-east" generates
{{site.prodname}}
[WorkloadEndpoint]({{ site.baseurl }}/reference/resources/workloadendpoint)
and
[NetworkPolicy]({{ site.baseurl }}/reference/resources/networkpolicy)
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
> within that same region.  
{: .alert .alert-info}

## Installation

To install a multi-region OpenStack deployment with Calico, proceed
region-by-region and follow [the normal procedure for adding Calico to an
OpenStack
region]({{ site.baseurl }}/getting-started/openstack/installation/overview),
except for these points:

1.  Only install a single etcd database (instead of one per region) and
    configure all of the regions to use that as their {{site.prodname}}
    datastore.

1.  In `/etc/calico/felix.cfg` on each compute host, add

    ```conf
    [global]
    OpenstackRegion = <region>
    ```

    where `<region>` is the name of the region that that compute host belongs to.

1.  In `/etc/neutron/neutron.conf` on each controller and compute node, add

    ```conf
    [calico]
    openstack_region = <region>
    ```

    where `<region>` is the name of the region that that node belongs to.

> **Note**: the value specified for `OpenstackRegion` and `openstack_region`
> must be a string of lower case alphanumeric characters or '-', starting and
> ending with an alphanumeric character.
{: .alert .alert-info}

> **Warning**: If the Felix and Neutron values here do not match, OpenStack
> will not be able to launch any VMs in that region, because the Neutron server
> for the region will think that there are no working compute nodes.
{: .alert .alert-danger}

### Configuring Openstack
You should now create networks in your Openstack regions as normal. e.g.
```bash
 neutron net-create --shared calico
 neutron subnet-create --gateway 10.65.0.1 --enable-dhcp --ip-version 4 --name calico-v4 calico 10.65.0.0/24
```

> **Note** that Calico networking provides a flat L3 network,
> so *subnets across all regions must not overlap*.
> For example, having 10.1.0.0/16 in one region and 10.2.0.0/16 in another
> would be fine, but 10.1.0.0/16 and 10.1.200.0/24 would not.
{: .alert .alert-info}

## Configuring cross-region policy

Suppose that:

- you have two regions

- you have a set of VMs in one region belonging to security group
  a7734e61-b545-452d-a3cd-0189cbd9747a

- you have a set of VMs in another region belonging to security group
  85cc3048-abc3-43cc-89b3-377341426ac5

- you want to allow the second set of VMs to connect to port 80 of the first
  set.

You need to have [calicoctl installed and configured for your
cluster](labels#configuring-operator-policy).  Once that is in place,
you could achieve the desired connectivity by using calicoctl to
configure this {{site.prodname}} policy:

```bash
calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: allow-tcp-80
spec:
  selector: "has(sg.projectcalico.org/openstack-a7734e61-b545-452d-a3cd-0189cbd9747a)"
  types:
  - Ingress
  ingress:
  - action: Allow
    protocol: TCP
    source:
      selector: "has(sg.projectcalico.org/openstack-85cc3048-abc3-43cc-89b3-377341426ac5)"
    destination:
      ports:
      - 80
EOF
```

In words, this says that connections to port 80 of the VMs with the label for
the a7734e61... security group are allowed from VMs (in any region) with
the label for the 85cc3048... security group.

In the `selector` fields, you can use any of the
[labels]({{ site.baseurl }}/networking/openstack/labels) that
{{site.prodname}} adds to OpenStack VM endpoints, to identify the set of VMs
that the policy should apply to, and the set of allowed (or denied) clients.
Here are some more examples of selectors to get you started:

-  To select all VMs in a region named "one": `projectcalico.org/namespace ==
   'openstack-region-one'`.

-  To select all VMs that are in a security group named "production", in *any*
   region: `has(sg-name.projectcalico.org/openstack-production)`.

You can also use `nets` or `notNets` instead of the `selector` field under
`source` or `destination`, to identify clients by IP address.
