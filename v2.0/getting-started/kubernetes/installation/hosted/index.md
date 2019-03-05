---
title: Calico Kubernetes Hosted Install
---

Calico can be installed on a Kubernetes cluster with a single command.

```
kubectl apply -f calico.yaml
```

We maintain several manifests.  Which one you use depends on the specific
requirements of your Calico installation:

#### [Standard Hosted Install](hosted)

This manifest installs Calico for use with an existing etcd cluster.  This is
the recommended hosted approach for deploying Calico in production.

#### [Kubeadm Hosted Install](kubeadm/)

This manifest installs Calico as well as a single node etcd cluster.  This is the recommended hosted approach
for getting started quickly with Calico in conjunction with tools like kubeadm.

#### [Etcdless Hosted Install](k8s-backend/)

This manifest installs Calico in a mode where it does not require its own etcd cluster.  This is an experimental
mode in which the Kubernetes API is used by Calico as its datastore.

## How it works

Each manifest contains all the necessary resources for installing Calico on each node in your Kubernetes cluster.

It installs the following Kubernetes resources:

- The `calico-config` ConfigMap, which contains parameters for configuring the install.
- Installs the `calico/node` container on each host using a DaemonSet.
- Installs the Calico CNI binaries and network config on each host using a DaemonSet.
- Runs the `calico/kube-policy-controller` in a Deployment.
- The `calico-etcd-secrets` Secret, which optionally allows for providing etcd TLS assets.

## Configuration options

The ConfigMap in `calico.yaml` provides a way to configure a Calico self-hosted installation.  It exposes
the following configuration parameters:

### Configuring the Pod IP range

Calico IPAM assigns IP addresses from
[IP pools]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/ippool). The
[standard](hosted) and [kubeadm](kubeadm/) manifests include an `ippool.yaml` file which
configures the default IP pool used by Calico.

To change the default IP range used for pods, modify the `cidr` section of the IP pool.

> **NOTE**
>
> The etcdless Calico manifest does not include an IP pool configuration, as IP allocation is done based on
the Kubernetes node.PodCIDR field, not Calico IP pools.

> **NOTE**
>
> The kubeadm Calico manifest also configures ipip encapsulation on the pool by default.

### Etcd Configuration

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

### Other Configuration Options

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

## Using calicoctl with a self-hosted installation

> **NOTE**
>
> The following information applies to the etcdv2 backend only. See the [etcdless hosted install](k8s-backend/)
for how to run calicoctl in an etcdless installation.

Using calicoctl is no different on a self-hosted installation.  However, the manifests above do not
install calicoctl.

You can install calicoctl by [downloading the appropriate release]({{site.baseurl}}/{{page.version}}/releases) to any
machine with access to your etcd cluster by setting `ETCD_ENDPOINTS`. For example:

```
ETCD_ENDPOINTS=http://etcd:2379 calicoctl get profile
```

You can also run calicoctl as a Kubernetes Pod directly using the following command:

```
kubectl apply -f -<<EOF
apiVersion: v1
kind: Pod
metadata:
  name: calicoctl
  namespace: kube-system
spec:
  hostNetwork: true
  containers:
  - name: calicoctl
    image: calico/ctl:v1.0.1
    command: ["/bin/sh", "-c", "while true; do sleep 3600; done"]
    env:
    - name: ETCD_ENDPOINTS
      valueFrom:
        configMapKeyRef:
          name: calico-config
          key: etcd_endpoints
EOF
```

You can then run calicoctl commands through the Pod with kubectl:

```
$ kubectl exec -ti -n kube-system calicoctl -- /calicoctl get profiles -o wide
NAME                 TAGS
k8s_ns.default       k8s_ns.default
k8s_ns.kube-system   k8s_ns.kube-system
```

> **NOTE**
>
> When calicoctl is run as a Pod, the calicoctl node suite of commands is not available.

See the [calicoctl reference guide]({{site.baseurl}}/{{page.version}}/reference/calicoctl) for more information.
