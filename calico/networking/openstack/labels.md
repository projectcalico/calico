---
title: Endpoint labels and operator policy
description: Use Calico labels to define policy for OpenStack VMs.
canonical_url: '/networking/openstack/labels'
---

When {{site.prodname}} represents an OpenStack VM as a {{site.prodname}} WorkloadEndpoint,
it puts labels on the WorkloadEndpoint to identify the project, security groups and
namespace that the VM belongs to.  The deployment operator can use these labels to
configure {{site.prodname}} policy that is additional to the policy defined by OpenStack
security groups, and that cannot be overridden by user-level security group config.

## VM endpoint labels

For the VM's OpenStack project (previously known as 'tenant'), those labels are:

| Label Name                                      | Value                          |
|-------------------------------------------------|--------------------------------|
| `projectcalico.org/openstack-project-id`        | `<the VM's project ID>`        |
| `projectcalico.org/openstack-project-name`      | `<the VM's project name>`      |
| `projectcalico.org/openstack-project-parent-id` | `<the VM's parent project ID>` |
|-------------------------------------------------|--------------------------------|

For each security group that the VM belongs to, those labels are:

| Label Name                                                  | Value                   |
|-------------------------------------------------------------|-------------------------|
| `sg.projectcalico.org/openstack-<security group ID>`        | `<security group ID>`   |
| `sg-name.projectcalico.org/openstack-<security group name>` | `<security group name>` |
|-------------------------------------------------------------|-------------------------|

For the VM's {{site.prodname}} namespace, the label is:

| Label Name                      | Value                |
|---------------------------------|----------------------|
| `projectcalico.org/namespace`   | `<namespace name>`   |
|---------------------------------|----------------------|

When `[calico] openstack_region` has been configured in `/etc/neutron/neutron.conf` (as
recommended for [multiple region deployments](multiple-regions)) the namespace will be
"openstack-region-" followed by the configured region name.  Otherwise it is simply
"openstack".

> **Note**: To allow {{site.prodname}} to provide the project name and parent ID labels,
> you must give Neutron the 'admin' role within your cluster:
> ```
> openstack role add --project service --user neutron admin
> ```
> or some equivalent privilege that allows the Neutron server to do admin-level queries of
> the Keystone database.  This is because {{site.prodname}}'s driver runs as part of the
> Neutron server, and needs to query the Keystone database for the information for those
> labels.  If Neutron isn't sufficiently privileged, {{site.prodname}} will fall back to
> not generating those labels.
{: .alert .alert-info}

> **Note**: {{site.prodname}} only allows certain characters in label names and values
> (alphanumerics, '-', '\_', '.' and '/'), so if a project or security group name normally
> has other characters, those will be replaced here by '\_'.  Also there is a length
> limit, so particularly long names may be truncated.
{: .alert .alert-info}

> **Note**: {{site.prodname}} does not support changing project name or security group
> name for a given ID associated with a VM after the VM has been created.  It is
> recommended that operators avoid any possible confusion here by not changing project
> name for a particular project ID or security group name for particular security group
> ID, post-creation.
{: .alert .alert-info}

## Configuring operator policy

Configuring operator policy requires the `calicoctl` executable, so you should
[install]({{ site.baseurl }}/maintenance/clis/calicoctl/install) and
[configure
calicoctl]({{ site.baseurl }}/maintenance/clis/calicoctl/configure/overview) if you
haven't done so already.

-  Calico for OpenStack deployments use an etcd datastore, so you should follow the
   instructions for an etcd datastore.

-  The settings you need for etcd endpoints, and TLS credentials if your deployment uses
   those, should match what you have in your
   [`neutron.conf`]({{ site.baseurl }}/networking/openstack/configuration)
   and [Felix]({{ site.baseurl }}/reference/felix/configuration)
   configurations.

## Example

Now you can configure {{site.prodname}} operator policy that will apply before the policy
that is derived from OpenStack security groups.  For example, to prevent any possible
communication between the "superman" and "lexluthor" projects, you could configure the
following.

```bash
calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-lexluthor-to-superman
spec:
  order: 10
  selector: "projectcalico.org/openstack-project-name == 'superman'"
  types:
  - Ingress
  ingress:
  - action: Deny
    source:
      selector: "projectcalico.org/openstack-project-name == 'lexluthor'"
---
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: deny-superman-to-lexluthor
spec:
  order: 10
  selector: "projectcalico.org/openstack-project-name == 'lexluthor'"
  types:
  - Ingress
  ingress:
  - action: Deny
    source:
      selector: "projectcalico.org/openstack-project-name == 'superman'"
EOF
```

> **Note**: {{site.prodname}} will enforce any policy with a specified `order` field (as
> here) before any policy derived from OpenStack security groups.
{: .alert .alert-info}
