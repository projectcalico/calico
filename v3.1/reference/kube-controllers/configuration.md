---
title: Configuring the Calico Kubernetes controllers
canonical_url: 'https://docs.projectcalico.org/v3.2/reference/kube-controllers/configuration'
---

The Calico Kubernetes controllers are primarily configured through environment variables. When running
the controllers as a Kubernetes pod, this is accomplished through the pod manifest `env`
section.

## The calico/kube-controllers container

The `calico/kube-controllers` container includes the following controllers:

1. policy controller: watches network policies and programs {{site.prodname}} policies.
1. profile controller: watches namespaces and programs {{site.prodname}} profiles.
1. workloadendpoint controller: watches for changes to pod labels and updates {{site.prodname}} workload endpoints.
1. node controller: watches for the removal of Kubernetes nodes and removes corresponding data from {{site.prodname}}.

By default, all four controllers are enabled.

### Configuring etcd access

The Calico Kubernetes controllers support the following environment variables to configure etcd access:

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| `ETCD_ENDPOINTS`    | The list of etcd nodes in your cluster. e.g `http://10.0.0.1:2379,http://10.0.0.2:2379`
| `ETCD_CA_CERT_FILE` | The full path to the CA certificate file for the Certificate Authority that signed the etcd server key/certificate pair. | path
| `ETCD_CERT_FILE`    | The full path to the client certificate file for accessing the etcd cluster. | path
| `ETCD_KEY_FILE`     | The full path to the client key file for accessing the etcd cluster. | path

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
