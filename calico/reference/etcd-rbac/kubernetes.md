---
title: Segmenting etcd on Kubernetes (basic)
description: Limit user access to Kubernetes and Calico components.
canonical_url: '/reference/etcd-rbac/kubernetes'
---

{% tabs %}
  <label:Operator,active:true>
<%

This document does not apply to operator installations of Calico.

%>

  <label:Manifest>
<%


When using etcd with RBAC, all components that access etcd must be configured
with the proper certificates. This document describes the users and roles
needed to segment etcd so that Kubernetes and {{site.prodname}} can only read and write
within their respected subtrees/prefixes. To configure more compartmentalized
configurations of the {{site.prodname}} components, see this addon:
[guide](kubernetes-advanced).

This guide assumes you are following the general
[Generating certificates](index) and using its guidance
for setting up certificates and etcd cluster, users, and roles.

## Why you might be interested in this guide

You are using Kubernetes and {{site.prodname}} that share an etcd datastore and you wish
to ensure that {{site.prodname}} and Kubernetes are unable to access each others' etcd
data.

## Needed etcd Roles

The following components need certificates with a Common Name that matches an
etcd user that has been given appropriate roles allowing access to the key
prefixes or paths listed below.

- kube-apiserver
  - Read and write access to `/registry/`.
  - The etcd user needs to be given the root role to perform compaction when
    using the etcd v3 API (this also means that Kubernetes will have
    full read and write access to v3 data).
- {{site.prodname}}
  - Read and write access to `/calico/`.

All certificate/key pairs that are referenced below are assumed to have been
created for the specific component with the information above.

## Kubernetes API server

The kube-apiserver is the only Kubernetes component that directly accesses etcd.
The flags required to provide the kube-apiserver with certificates for
accessing an etcd cluster are:

- `--etcd-cafile=<CA certificate`
- `--etcd-certfile=<certificate with etcd username as CN>`
- `--etcd-keyfile=<key for the above certificate>`

Setting these will depend on the method used to deploy Kubernetes so refer
to your integrator's documentation for help setting these flags.

## Updating a hosted {{site.prodname}} manifest

To deploy {{site.prodname}} with the CA and {{site.prodname}}-specific certificate/key pair,
use [this manifest template]({{site.data.versions.first.manifests_url}}/manifests/calico-etcd.yaml)
with the modifications described below. The same information could be added to
or updated in other manifests but the linked one is the most straight forward
example.

The pieces that would need updating are:

- The `calico-config` ConfigMap lines with `etcd_ca`, `etcd_cert`, and
  `etcd_key` should be updated as follows
  ```yaml
  etcd_ca: "/calico-secrets/etcd-ca"
  etcd_cert: "/calico-secrets/etcd-cert"
  etcd_key: "/calico-secrets/etcd-key"
  ```

- The Secret named `calico-etcd-secrets` needs to be updated with the CA and
  cert/key. The information stored in `data` in a Secret needs to be base64
  encoded. The files can be converted to base64 encoding by doing a command
  like `cat <file> | base64 -w 0` on each file and then inserting the output
  to the appropriate field.
    - The `etcd-key` field needs the base64 encoded file contents from the
	  key file.
	- The `etcd-cert` field needs the base64 encoded file contents from the
	  certificate file.
	- The `etcd-ca` field needs the base64 encoded file contents from the
	  Certificate Authority certificate.

- If sharing an etcd cluster with Kubernetes, disable etcd compaction in the
  calico-kube-controllers deployment by setting the `COMPACTION_PERIOD` environment variable to 0.

Once the updates above are made then the manifest can be applied in the normal manner.

%>

{% endtabs %}
