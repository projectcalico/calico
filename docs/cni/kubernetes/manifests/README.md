# Calico Kubernetes Hosted Install

This directory contains Kubernetes manifests to deploy Calico on top of Kubernetes.

- `calico-config.yaml`: Contains a Kubernetes ConfigMap for configuring the deployment.  Make sure the values
in this file match your desired configuration. This also includes a Kubernetes Secret for configuring TLS for etcd access.

- `calico-hosted.yaml`: Contains a Kubernetes DaemonSet which installs and runs Calico on each Kubernetes master and node.
This also includes a ReplicaSet which deploys the Calico Kubernetes policy controller.

Note that the Kubernetes hosted installation method is experimental and subject to change.

# How it works

The `calico-hosted.yaml` file contains all the necessary resources for installing Calico on each node in your Kubernetes cluster.

It does the following things:

- Installs the `calico/node` container on each host using a DaemonSet.
- Installs the Calico CNI binaries and network config on each host using a DaemonSet.
- Runs the `calico/kube-policy-controller` pod as a ReplicaSet.

# Configuration options

The `calico-config.yaml` provides a way to configure a Calico self-hosted installation.  It exposes
the following configuration parameters:

## Etcd Configuration

By default, these manifests do not configure secure access to etcd and assume an etcd proxy is running on each host.  The following configuration
options let you specify custom etcd cluster endpoints as well as TLS.  

To use these manifests with a TLS enabled etcd cluster you must do the following:

- Populate the `calico-etcd-secrets` Secret with the following files: `etcd-ca`, `etcd-key`, `etcd-cert`.
- Populate the following options in the ConfigMap which will trigger the various services to expect the provided TLS assets: `etcd_ca`, `etcd_key`, `etcd_cert`

### etcd_endpoints

A comma separated list of etcd nodes. e.g `https://etcd0:2379,...` 

The default in the provided manifest uses localhost, and assumes that an etcd proxy is running on each node.

### etcd_ca 

The location of the CA mounted in the pods deployed by the DaemonSet. To enable, set to `/calico-secrets/etcd-ca`

### etcd_key

`etcd_key`: The location of the client cert mounted in the pods deployed by the DaemonSet. To enable, set to `/calico-secrets/etcd-cert`

### etcd_cert

The location of the client key mounted in the pods deployed by the DaemonSet. To enable, set to `/calico-secrets/etcd-key`

## Other Configuration Options

### enable_bgp 

Whether or not to run Calico BGP.  If false, then BGP will be disabled and Calico will enforce policy only.

### cni_network_config

The CNI network configuration to install on each node.  This field supports the following template fields, which will 
be filled in automatically by the `calico/cni` container:

- `__KUBERNETES_SERVICE_HOST__`: This will be replaced with the Kubernetes Service clusterIP. e.g 10.0.0.1 
- `__KUBERNETES_SERVICE_PORT__`: This will be replaced with the Kubernetes Service port. e.g 443
- `__SERVICEACCOUNT_TOKEN__`: This will be replaced with the serviceaccount token for the namespace.  Requires that Kubernetes be configured to create serviceaccount tokens.
- `__ETCD_ENDPOINTS__`: This will be replaced with the etcd cluster specified in the ETCD_ENDPOINTS environment variable. e.g http://127.0.0.1:2379
- `__KUBECONFIG_FILEPATH__`: The path to the automatically generated kubeconfig file in the same directory as the CNI network config file.
- `__ETCD_KEY_FILE__`: The path to the etcd key file installed to the host, empty if no key present.
- `__ETCD_CERT_FILE__`: The path to the etcd cert file installed to the host, empty if no cert present.
- `__ETCD_CA_CERT_FILE__`: The path to the etcd CA file installed to the host, empty if no CA present.
