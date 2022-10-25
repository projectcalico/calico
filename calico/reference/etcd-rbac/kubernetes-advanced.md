---
title: Segmenting etcd on Kubernetes (advanced)
description: Limit user access to Calico components or calicoctl.
canonical_url: '/reference/etcd-rbac/kubernetes-advanced'
---

{% tabs %}
  <label:Operator,active:true>
<%

This document does not apply to operator installations of Calico.

%>

  <label:Manifest>
<%

This document describes advanced segmentation of the etcd roles to limit
access of individual {{site.prodname}} components or to limit calicoctl user access.
It assumes you have followed [this guide](kubernetes) for initial etcd
RBAC configuration of {{site.prodname}} and Kubernetes.

## Why you might be interested in this guide

You want to limit access on a per-{{site.prodname}} component level or create limited
access roles for calicoctl to the etcd datastore.

## Components that need etcd Roles

The following components need certificates with a Common Name that matches an
etcd user that has been given appropriate roles allowing access to the key
prefixes or paths listed or linked below.
- [cni-plugin](calico-etcdv3-paths#cni-plugin)
- [{{site.prodname}} Kubernetes controllers](calico-etcdv3-paths#calicokube-controllers)
- [{{site.nodecontainer}}](calico-etcdv3-paths#caliconode)
- It may also be useful to create a certificate key pair for use with
  calicoctl, even creating specific ones for
  [read only access](calico-etcdv3-paths#calicoctl-read-only-access),
  [policy editor access](calico-etcdv3-paths#calicoctl-policy-editor-access),
  and [full read/write access](calico-etcdv3-paths#calicoctl-full-readwrite-access).

All certificate/key pairs that are referenced below are assumed to have been
created for the specific component with the information above.

## {{site.prodname}} components

Once the certificates are generated and the users and roles have been setup
in etcd the components using them must be configured. Here are the same
components listed above and links to their detailed configuration pages:
- [cni-plugin]({{ site.baseurl }}/reference/cni-plugin/configuration)
- [{{site.prodname}} Kubernetes controllers]({{ site.baseurl }}/reference/kube-controllers/configuration)
- [{{site.nodecontainer}}]({{ site.baseurl }}/reference/node/configuration)
- [calicoctl](/maintenance/clis/calicoctl/install)

Below are examples and suggestions when using a hosted {{site.prodname}} install where
the {{site.prodname}} components are launched through a Kubernetes manifest file, this
is not required and the configuration could be achieved by configuring services
that run outside of Kubernetes.

### Per component certificate setup

A setup that needs a certificate for each component is possible while using a
hosted manifest. This setup requires a certificate for each different {{site.prodname}}
component type listed above (cni-plugin, {{site.prodname}} Kubernetes controllers, and
`{{site.nodecontainer}}`).

This setup needs similar updates to the manifest like what is described in
[Using etcd RBAC to segment Kubernetes and {{site.prodname}}: Updating a hosted {{site.prodname}} manifest](kubernetes#updating-a-hosted-Calico-manifest),
with the in addition to those updates a separate Secret for *each* component
must be created which holds the CA, certificate, and key data base64 encoded.
Then the specific Secret for each component must be in the `volumes` list
for the correct pod and the `volumeMounts` for the appropriate container must
reference the volume for the `/calico-secrets` mountPath.

### Per node per component certificate setup

While the above is a good step toward locking down access to etcd and would
probably satisfy the needs of many, there is a third option that could
utilize a different certificate for each component for each node. This type
of setup can be achieved multiple ways and will be left as an exercise for
the implementor. Some possibilities for achieving this are:
- Installing and starting the {{site.prodname}} components with a configuration management
  tool which installs and configures the certificates.
- Creating a manifest with a side car container that pulls the proper
  certificate information from Vault or other secret management tool.

%>

{% endtabs %}
