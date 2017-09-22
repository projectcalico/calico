---
title: Configuring the Calico policy controller
---

The policy controller is primarily configured through environment variables. When running
the policy controller as a Kubernetes pod, this is accomplished through the pod manifest `env`
section.

## The calico/kube-policy-controller container

### Configuring etcd access

The policy controller supports the following environment variables to configure
etcd access:

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| `ETCD_ENDPOINTS`    | The list of etcd nodes in your cluster. e.g `http://10.0.0.1:2379,http://10.0.0.2:2379`
| `ETCD_CA_CERT_FILE` | The full path to the CA certificate file for the Certificate Authority that signed the etcd server key/certificate pair. | path
| `ETCD_CERT_FILE`    | The full path to the client certificate file for accessing the etcd cluster. | path
| `ETCD_KEY_FILE`     | The full path to the client key file for accessing the etcd cluster. | path

The `*_FILE` variables are _paths_ to the corresponding certificates/keys. As such, when the policy controller is running as a Kubernetes pod, you
must ensure that the files exist within the pod. This is usually done in one of two ways:

* Mount the certificates from the host. This requires that the certs be present on the host running the policy controller.
* Use Kubernetes [Secrets](http://kubernetes.io/docs/user-guide/secrets/) to mount the certificates into the Pod as files.

### Configuring Kubernetes API access

The policy controller must have read access to the Kubernetes API in order to monitor NetworkPolicy, Pod, and Namespace events.

When running the policy controller as a self-hosted Kubernetes Pod, Kubernetes API access is [configured automatically][in-cluster-config] and
no additional configuration is required. However, the controller also supports an explicit [kubeconfig][kubeconfig] file override to
configure API access if needed.

### Other configuration

The following environment variables can be used to configure the policy controller.

| Environment   | Description | Schema |
| ------------- | ----------- | ------ |
| `LOG_LEVEL`     | Minimum log level to be displayed. | debug, info, warning, error |
| `KUBECONFIG`    | Path to a kubeconfig file for kubernetes API access | path |

[in-cluster-config]: https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/#accessing-the-api-from-a-pod
[kubeconfig]: https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/
