---
title: Endpoint Labels
canonical_url: 'https://docs.projectcalico.org/master/usage/openstack/labels'
---

When {{site.prodname}} represents an OpenStack VM as a {{site.prodname}} WorkloadEndpoint,
it puts labels on the WorkloadEndpoint to identify the project, security groups and
namespace that the VM belongs to.

For the VM's OpenStack project (previously known as 'tenant'), those labels are:

| Label Name                                 | Value                     |
|--------------------------------------------|---------------------------|
| `projectcalico.org/openstack-project-id`   | `<the VM's project ID>`   |
| `projectcalico.org/openstack-project-name` | `<the VM's project name>` |
|--------------------------------------------|---------------------------|

For each security group that the VM belongs to, those labels are:

| Label Name                                                  | Value                   |
|-------------------------------------------------------------|-------------------------|
| `sg.projectcalico.org/openstack-<security group ID>`        | `<security group name>` |
| `sg-name.projectcalico.org/openstack-<security group name>` | `<security group ID>`   |
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

> **Note**: Calico only allows certain characters in label names and values
> (alphanumerics, '-', '\_', '.' and '/'), so if a project or security group name normally
> has other characters, those will be replaced here by '\_'.  Also there is a length
> limit, so particularly long names may be truncated.

> **Note**: Calico does not support changing project name or security group name for a
> given ID associated with a VM after the VM has been created.  It is recommended that
> operators avoid any possible confusion here by not changing project name for a
> particular project ID or security group name for particular security group ID,
> post-creation.
