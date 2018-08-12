---
title: Configuring the Calico Kubernetes controllers
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/reference/kube-controllers/configuration'
---

The {{site.prodname}} Kubernetes controllers are primarily configured through environment variables. When running
the controllers as a Kubernetes pod, this is accomplished through the pod manifest `env`
section.

## The calico/kube-controllers container

The `calico/kube-controllers` container includes the following controllers:

1. policy controller: watches network policies and programs {{site.prodname}} policies.
1. profile controller: watches namespaces and programs {{site.prodname}} profiles.
1. workloadendpoint controller: watches for changes to pod labels and updates {{site.prodname}} workload endpoints.
1. node controller: watches for the removal of Kubernetes nodes and removes corresponding data from {{site.prodname}}.

By default, the following controllers are enabled: profile, policy, workloadendpoint

### Configuring etcd access

The {{site.prodname}} Kubernetes controllers support the following environment variables to configure etcd access:

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| `ETCD_ENDPOINTS`    | Comma-delimited list of etcd endpoints to connect to. Example: `http://10.0.0.1:2379,http://10.0.0.2:2379`.
| `ETCD_CA_CERT_FILE` | Path to the file containing the root certificate of the CA that issued the etcd server certificate. Configures the Kubernetes controllers to trust the signature on the certificates provided by the etcd server. To disable authentication of the server by the Kubernetes controllers, set the value to `none`. | path
| `ETCD_CERT_FILE`    | Path to the file containing the client certificate issued to the Kubernetes controllers. Enables the Kubernetes controllers to participate in mutual TLS authentication and identify themselves to the etcd server. Example: `/etc/kube-controllers/cert.pem` | path
| `ETCD_KEY_FILE`     | Path to the file containing the private key of the Kubernetes controllers' client certificate. Enables the Kubernetes controllers to participate in mutual TLS authentication and identify themselves to the etcd server. Example: `/etc/kube-controllers/key.pem` | path

The `*_FILE` variables are _paths_ to the corresponding certificates/keys. As such, when the controllers are running as a Kubernetes pod, you
must ensure that the files exist within the pod. This is usually done in one of two ways:

* Mount the certificates from the host. This requires that the certificates be present on the host running the controller.
* Use Kubernetes [Secrets](http://kubernetes.io/docs/user-guide/secrets/) to mount the certificates into the pod as files.

### Configuring Kubernetes API access

The controllers must have read access to the Kubernetes API in order to monitor `NetworkPolicy`, `Pod`, and `Namespace` events.

When running the controllers as a self-hosted Kubernetes Pod, Kubernetes API access is [configured automatically][in-cluster-config] and
no additional configuration is required. However, the controllers can also be configured to use an explicit [kubeconfig][kubeconfig] file override to
configure API access if needed.

### Other configuration

The following environment variables can be used to configure the {{site.prodname}} Kubernetes controllers.

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| `ENABLED_CONTROLLERS` | Which controllers to run | policy, profile, workloadendpoint, node |
| `LOG_LEVEL`     | Minimum log level to be displayed. | debug, info, warning, error |
| `KUBECONFIG`    | Path to a kubeconfig file for Kubernetes API access | path |

[in-cluster-config]: https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/#accessing-the-api-from-a-pod
[kubeconfig]: https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/

## About each controller

### Node controller

The node controller automatically cleans up configuration for nodes that no longer exist.

The node controller is not enabled by default. However, the {{site.prodname}} Kubernetes manifests do enable this controller.

To enable the node controller, perform the following two steps.

1. Add "node" to the list of enabled controllers in the environment for kube-controllers. For example: `ENABLED_CONTROLLERS=workloadendpoint,profile,policy,node`
1. Configure {{site.nodecontainer}} with a Kubernetes node reference by adding the following snippet to the environment section of the {{site.noderunning}} daemon set.
```
- name: CALICO_K8S_NODE_REF
  valueFrom:
    fieldRef:
      fieldPath: spec.nodeName
```

### Policy controller

The policy controller syncs Kubernetes network policies to the {{site.prodname}} data store.

The policy controller is enabled by default.


### Workload endpoint controller

The workload endpoint controller automatically syncs Kubernetes pod label changes to the {{site.prodname}} data store by updating
the corresponding workload endpoints appropriately.

The workload endpoint controller is enabled by default.

### Profile controller

The profile controller syncs Kubernetes namespace label changes to the {{site.prodname}} data store.

The profile controller is enabled by default.
