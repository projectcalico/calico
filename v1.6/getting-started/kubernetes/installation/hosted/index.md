---
title: Calico Kubernetes Hosted Install
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/kubernetes/installation/hosted/hosted'
---

This document describes deploying Calico on Kubernetes using Kubernetes manifests.  Note that the Kubernetes hosted installation method is experimental and subject to change, and requires Kubernetes v1.4.0+.

- [`calico.yaml`](calico.yaml): Deploys Calico on Kubernetes.  Assumes an etcd cluster is available - modify `etcd_endpoints` to direct Calico at the correct cluster.

- [`kubeadm/calico.yaml`](kubeadm/calico.yaml):  Installs Calico as well as a single node etcd cluster for cases where etcd is not already available (e.g kubeadm clusters).  See [here](kubeadm) for more information.

To install Calico, download one of the above manifests depending on your deployment, and run the following command:

```shell
kubectl apply -f calico.yaml
```

> **NOTE**
>
> If using your own etcd cluster, make sure you configure the provided ConfigMap with the location of the cluster before running the above command. 

## How it works

The `calico.yaml` file contains all the necessary resources for installing Calico on each node in your Kubernetes cluster.

It installs the following Kubernetes resources: 

- The `calico-config` ConfigMap, which contains parameters for configuring the install.
- Installs the `calico/node` container on each host using a DaemonSet.
- Installs the Calico CNI binaries and network config on each host using a DaemonSet.
- Runs the `calico/kube-policy-controller` pod as a ReplicaSet.
- The `calico-etcd-secrets` Secret, which optionally allows for providing etcd TLS assets.

## Configuration options

The ConfigMap in `calico.yaml` provides a way to configure a Calico self-hosted installation.  It exposes
the following configuration parameters:

## Etcd Configuration

By default, these manifests do not configure secure access to etcd and assume an etcd proxy is running on each host.  The following configuration
options let you specify custom etcd cluster endpoints as well as TLS.  

The following table outlines the supported ConfigMap options for etcd:
 
| Option                 | Description    | Default 
|------------------------|----------------|----------
| etcd_endpoints         | A comma separated list of etcd nodes. | http://127.0.0.1:2379
| etcd_ca                | The location of the CA mounted in the pods deployed by the DaemonSet. | None
| etcd_key               | The location of the client cert mounted in the pods deployed by the DaemonSet. | None
| etcd_cert              | The location of the client key mounted in the pods deployed by the DaemonSet. | None

To use these manifests with a TLS enabled etcd cluster you must do the following:

- Populate the `calico-etcd-secrets` Secret with the contents of the following files: 
  - `etcd-ca`
  - `etcd-key`
  - `etcd-cert`
- Populate the following options in the ConfigMap which will trigger the various services to expect the provided TLS assets: 
  - `etcd_ca: /calico-secrets/etcd-ca`
  - `etcd_key: /calico-secrets/etcd-key`
  - `etcd_cert: /calico-secrets/etcd-cert`


## Other Configuration Options

The following table outlines the remaining supported ConfigMap options: 

| Option                 | Description         | Default 
|------------------------|---------------------|----------
| calico_backend         | The backend to use. | bird 
| cni_network_config     | The CNI Network config to install on each node.  Supports templating as described below. | 


### CNI Network Config Template Support

The `cni_network_config` configuration option supports the following template fields, which will 
be filled in automatically by the `calico/cni` container:

| Field                                 | Substituted with 
|---------------------------------------|----------------------------------
| `__KUBERNETES_SERVICE_HOST__`         | The Kubernetes Service ClusterIP. e.g 10.0.0.1 
| `__KUBERNETES_SERVICE_PORT__`         | The Kubernetes Service port. e.g 443
| `__SERVICEACCOUNT_TOKEN__`            | The serviceaccount token for the namespace, if one exists.
| `__ETCD_ENDPOINTS__`                  | The etcd endpoints specified in etcd_endpoints. 
| `__KUBECONFIG_FILEPATH__`             | The path to the automatically generated kubeconfig file in the same directory as the CNI network config file.
| `__ETCD_KEY_FILE__`                   | The path to the etcd key file installed to the host, empty if no key present.
| `__ETCD_CERT_FILE__`                  | The path to the etcd cert file installed to the host, empty if no cert present.
| `__ETCD_CA_CERT_FILE__`               | The path to the etcd CA file installed to the host, empty if no CA present.
