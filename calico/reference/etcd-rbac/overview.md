---
title: Setting up etcd certificates for RBAC
description: Protect your etcd datastore by restricting operation permissions.
canonical_url: '/reference/etcd-rbac/index'
---

{% tabs %}
  <label:Operator,active:true>
<%

This document does not apply to operator installations of Calico.

%>

  <label:Manifest>
<%

When using etcd it is a good idea to protect the data stored there. This is
even more true when you have multiple components using a common etcd cluster.
This set of tutorials guides you through the process of locking down and
segmenting access to the data in your etcd datastore.

## Why you might be interested in this guide

- You want to restrict the operations that support staff are able to perform
  to minimize accidental corruption or deletion of etcd data.
- You want to use a single etcd cluster for {{site.prodname}} and Kubernetes (rather than
  having an etcd cluster for {{site.prodname}} and a separate etcd cluster for Kubernetes.
- You want to restrict the read/write access of the various {{site.prodname}} components
  as an additional safety measure.

## Configuration Concept

The central piece that will link the components together is the Certificate
Authority(CA). It will be used to
generate certificates and keys that the etcd members (and proxies) and components
(like {{site.prodname}} and Kubernetes) will need to authenticate with the etcd cluster.
Because all the certificates will be generated from the same CA and all the
components will have the CA certificate, those connections can be mutually
authenticated.

The certificates and keys generated for the components accessing etcd will allow
access to particular key prefixes or paths in etcd. The certificates are linked
with an etcd username by being generated with a Common Name (CN) that matches
the etcd username. The etcd username is linked with a role or multiple roles
that allow access to the appropriate data in etcd.

## Requirements

- If using only the v2 API with etcd, as {{site.prodname}} does, then the minimum etcd
  version required is 3.0.12.
- If using the v3 API with etcd, as Kubernetes can, then the minimum etcd
  version required is 3.2. (Note: The 3.x version of etcd supports both the v2
  and the v3 API.)

## Setup

1. [Generate CA, certificates, and keys](certificate-generation).
2. Setup etcd with the CA certificate and the certificates generated in step 1.
   See the
   [etcd security op-guide](https://coreos.com/etcd/docs/latest/op-guide/security.html){:target="_blank"}
   for help configuing etcd.
3. [Create Users and Roles in etcd](users-and-roles).
4. Configure components. For example:
   - [Setting up Kubernetes with {{site.prodname}} utilizing etcd RBAC](kubernetes).
   - [Advanced Kubernetes set ups utilizing etcd RBAC](kubernetes-advanced).

%>

{% endtabs %}
