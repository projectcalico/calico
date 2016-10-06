---
title: Calico Kubernetes Hosted Install
---

This document describes deploying Calico on Kubernetes using Kubernetes manifests.  Note that the Kubernetes hosted installation method is experimental and subject to change.

- [`calico.yaml`](calico.yaml): Contains a Kubernetes DaemonSet 
which installs and runs Calico on each Kubernetes master and node. This also includes a ReplicaSet which deploys 
the Calico Kubernetes policy controller, and a ConfigMap which allows for configuration of the install.

To install Calico, download [calico.yaml](calico.yaml) and run the following command:

```shell
kubectl apply -f calico.yaml
```

# How it works

The `calico.yaml` file contains all the necessary resources for installing Calico on each node in your Kubernetes cluster.

It does the following things:

- The `calico-config` ConfigMap, which contains parameters for configuring the install.
- Installs the `calico/node` container on each host using a DaemonSet.
- Installs the Calico CNI binaries and network config on each host using a DaemonSet.
- Runs the `calico/kube-policy-controller` pod as a ReplicaSet.

# Configuration options

The ConfigMap in `calico.yaml` provides a way to configure a Calico self-hosted installation.  It exposes
the following configuration parameters:

### etcd_endpoints

The location of your etcd cluster.  The default in the provided manifest assumes that an etcd proxy is running on each node.

### enable_bgp

Whether or not to run Calico BGP.  If false, then BGP will be disabled and Calico will enforce policy only.

### cni_network_config

The CNI network configuration to install on each node.  This field supports the following template fields, which will
be filled in automatically by the `calico/cni` container:

- `__KUBERNETES_SERVICE_HOST__`: This will be replaced with the Kubernetes Service clusterIP. e.g 10.0.0.1
- `__KUBERNETES_SERVICE_PORT__`: This will be replaced with the Kubernetes Service port. e.g 443
- `__SERVICEACCOUNT_TOKEN__`: This will be replaced with the serviceaccount token for the namespace.  Requires that Kubernetes be configured to create serviceaccount tokens.
- `__ETCD_ENDPOINTS__`: This will be replaced with the etcd cluster specified in the ETCD_ENDPOINTS environment variable. e.g http://127.0.0.1:2379
- `__KUBECONFIG_FILENAME__`: The name of the automatically generated kubeconfig file in the same directory as the CNI network config file.
