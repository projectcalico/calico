---
title: Creating users and roles
redirect_from: latest/reference/etcd-rbac/users-and-roles
canonical_url: 'https://docs.projectcalico.org/v3.6/reference/advanced/etcd-rbac/users-and-roles'
---

Providing role based access control within etcd requires the following:
-  Creation of etcd roles which provide appropriate access to the specific set
   of etcd keys required by the role
-  Creation of etcd users who are assigned roles


> **Note**: The etcd release 3.x+ supports both v2 and v3 of its API. The etcd server
> keeps the roles and users separate, this means that if a user/role is created
> with the v2 API it will not appear in the v3 API. When adding roles and users
> they must be added through the API version that matches the version the
> component will be using. This concern can be ignored if all roles and users
> are added through both API versions.
{: .alert .alert-info}


## Users and Roles creation guides

Use the following guides to setup your users, roles, and assignment of roles
to users. Since this document assumes that you have configured your etcd cluster
to use certificates, you must pass a proper CA and cert/key pair to the
commands used in the below guides.

- [etcd v2 guide](https://coreos.com/etcd/docs/latest/v2/authentication.html)
- [etcd v3 guide](https://coreos.com/etcd/docs/latest/op-guide/authentication.html)

## Suggestions for your roles and users

- Create a root user under both the v2 and v3 etcd API to ensure access after
  you enable authentication on your cluster.
- Create a guest role (particularly on the v2 API) and ensure it does not have
  access to your cluster.
- Enable authentication on both the v2 and the v3 API, enabling it on one does
  not enable it on the other. Make sure you enable authentication only after
  you have created your root users.
- Ensure your usernames match the Common Name set in your certificates to allow
  access without specifying the username to your components.
