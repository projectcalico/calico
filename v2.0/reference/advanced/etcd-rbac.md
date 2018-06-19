---
title: Configuring a Calico Role for etcdv2 RBAC
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/reference/advanced/etcd-rbac/'
---

Calico writes all of its data in a `/calico/` directory of etcd.
To function properly with [etcdv2's RBAC](https://coreos.com/etcd/docs/latest/authentication.html),
it will need the following permissions:

- R/W access to `/calico`
- R/W access to `/calico/*`

The following example will create a role called `calico-role` with the necessary
permissions:

```
$ etcdctl role add calico-role
$ etcdctl role grant calico-role -path '/calico' -readwrite
$ etcdctl role grant calico-role -path '/calico/*' -readwrite
```

### Configuring calicoctl to use authenticated etcd access

To configure Calico to use the newly created role, each component will
individually need to be supplied with the role name and password. See the relevant
component configuration guide:

- [calicoctl]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/etcdv2)
