---
title: Endpoint Labels
redirect_from: latest/usage/openstack/labels
canonical_url: 'https://docs.projectcalico.org/master/usage/openstack/labels'
---

When {{site.prodname}} represents an OpenStack VM as a {{site.prodname}} WorkloadEndpoint,
it puts labels on the WorkloadEndpoint to identify the project and security groups that
the VM belongs to.

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

> **Note**: Calico only allows certain characters in label names and values
> (alphanumerics, '-', '\_', '.' and '/'), so if a project or security group name normally
> has other characters, those will be replaced here by '\_'.  Also there is a length
> limit, so particularly long names may be truncated.

> **Note**: Calico does not support changing project name or security group name for a
> given ID associated with a VM after the VM has been created.  It is recommended that
> operators avoid any possible confusion here by not changing project name for a
> particular project ID or security group name for particular security group ID,
> post-creation.
