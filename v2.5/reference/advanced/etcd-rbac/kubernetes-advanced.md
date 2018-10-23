---
title: Advanced etcd segmentation for Calico
canonical_url: 'https://docs.projectcalico.org/v3.3/reference/advanced/etcd-rbac/kubernetes-advanced'
---

This document describes advanced segmentation of the etcd roles to limit
access of individual Calico components or to limit calicoctl user access.
It assumes you have followed [this guide](kubernetes) for initial etcd
RBAC configuration of Calico and Kubernetes.

## Why you might be interested in this guide

You want to limit access on a per-Calico component level or create limited
access roles for calicoctl to the etcd datastore.

## Components that need etcd Roles

The following components need certificates with a Common Name that matches an
etcd user that has been given appropriate roles allowing access to the key
prefixes or paths listed or linked below.
- [cni-plugin](calico-etcdv2-paths#cni-plugin)
- [Calico policy controller](calico-etcdv2-paths#calicokube-policy-controller)
- [calico/node](calico-etcdv2-paths#caliconode)
- It may also be useful to create a certificate key pair for use with
  calicoctl, even creating specific ones for
  [read only access](calico-etcdv2-paths#calicoctl-read-only-access),
  [policy editor access](calico-etcdv2-paths#calicoctl-policy-editor-access),
  and [full read/write access](calico-etcdv2-paths#calicoctl-full-readwrite-access).

All certificate/key pairs that are referenced below are assumed to have been
created for the specific component with the information above.

## Calico components

Once the certificates are generated and the users and roles have been setup
in etcd the components using them must be configured.  Here are the same
components listed above and links to their detailed configuration pages:
- [cni-plugin]({{site.baseurl}}/{{page.version}}/reference/cni-plugin/configuration)
- [Calico policy controller]({{site.baseurl}}/{{page.version}}/reference/policy-controller/configuration)
- [calico/node]({{site.baseurl}}/{{page.version}}/reference/node/configuration)
- [calicoctl]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/etcdv2)

Below are examples and suggestions when using a hosted Calico install where
the Calico components are launched through a Kuberenetes manifest file, this
is not required and the configuration could be achieved by configuring services
that run outside of Kubernetes.

### Per component cert setup

A setup that needs a certificate for each component is possible while using a
hosted manifest.  This setup requires a certificate for each different Calico
component type listed above (cni-plugin, Calico policy controller, and
calico/node).

This setup needs similar updates to the manifest like what is described in
[Using etcd RBAC to segment Kubernetes and Calico: Updating a hosted Calico manifest](kubernetes#updating-a-hosted-Calico-manifest),
with the in addition to those updates a separate Secret for *each* component
must be created which holds the CA, certificate, and key data base64 encoded.
Then the specific Secret for each component must be in the `volumes` list
for the correct pod and the `volumeMounts` for the appropriate container must
reference the volume for the `/calico-secrets` mountPath.

### Per node per component cert setup

While the above is a good step toward locking down access to etcd and would
probably satisfy the needs of many there is a third option that could
utilize a different certificate for each component for each node.  This type
of setup can be achieved multiple ways and will be left as an exercise for
the implementor.  Some possibilities for achieving this are:
- Installing and starting the Calico components with a configuration management
  tool which installs and configures the certificates.
- Creating a manifest with a side car container that pulls the proper
  certificate information from Vault or other secret management tool.
