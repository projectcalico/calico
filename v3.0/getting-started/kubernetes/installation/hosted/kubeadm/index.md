---
title: kubeadm Hosted Install
canonical_url: https://docs.projectcalico.org/v3.6/getting-started/kubernetes/installation/
---

This document outlines how to install {{site.prodname}} on a cluster initialized with
[kubeadm](http://kubernetes.io/docs/getting-started-guides/kubeadm/).  {{site.prodname}}
is compatible with kubeadm-created clusters, as long as the [requirements](#requirements) are met.

## Requirements

For {{site.prodname}} to be compatible with your kubeadm-created cluster:

* It must be running at least Kubernetes v1.7

* There should be no other CNI network configurations installed in /etc/cni/net.d (or equivalent directory)

* The kubeadm flag `--pod-network-cidr` must be set when creating the cluster with `kubeadm init`
  and the CIDR(s) specified with the flag must match {{site.prodname}}'s IP pools. The default
  IP pool configured in {{site.prodname}}'s manifests is `192.168.0.0/16`

* The CIDR specified with the kubeadm flag `--service-cidr` must not overlap with
  {{site.prodname}}'s IP pools

  * The default CIDR for `--service-cidr` is `10.96.0.0/12`

  * The default IP pool configured in {{site.prodname}}'s manifests is `192.168.0.0/16`

You can create a cluster compatible with these manifests by following [the official kubeadm guide](http://kubernetes.io/docs/getting-started-guides/kubeadm/).

## Installing {{site.prodname}} with a Kubernetes-hosted etcd

As a non-production quick start, to install {{site.prodname}} with a single-node dedicated etcd cluster,
running as a Kubernetes pod:

1. Ensure your cluster meets the [requirements](#requirements) (or recreate it if not).

2. Apply the single-node etcd manifest:

   ```shell
   kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubeadm/1.7/calico.yaml
   ```

   > **Note**: You can also
   > [view the YAML in your browser](1.7/calico.yaml){:target="_blank"}.
   {: .alert .alert-info}

## Installing with an existing etcd datastore

To install {{site.prodname}}, configured to use an etcd that you have already set-up:

1. Ensure your cluster meets the [requirements](#requirements) (or recreate it if not).

2. Follow [the main etcd datastore instructions](../hosted).

## Kubernetes datastore

To install {{site.prodname}}, configured to use the Kubernetes API as its sole data source:

1. Ensure your cluster meets the [requirements](#requirements) (or recreate it if not).

2. Follow [the main Kubernetes datastore instructions](../kubernetes-datastore).

## Using calicoctl in a kubeadm cluster

The simplest way to use calicoctl in kubeadm is by running it as a pod.
See [Installing calicoctl as a container](/{{page.version}}/usage/calicoctl/install#installing-calicoctl-as-a-container) for more information.
