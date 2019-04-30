---
title: Configuring the Calico Kubernetes controllers
redirect_from: latest/reference/kube-controllers/configuration
---

The {{site.prodname}} Kubernetes controllers are deployed in a Kubernetes cluster. The different controllers monitor the Kubernetes API
and perform actions based on cluster state.

The controllers are primarily configured through environment variables. When running
the controllers as a Kubernetes pod, this is accomplished through the pod manifest `env`
section.

## The {{site.imageNames["kubeControllers"]}} container

The `{{site.imageNames["kubeControllers"]}}` container includes the following controllers:

1. policy controller: watches network policies and programs {{site.prodname}} policies.
1. namespace controller: watches namespaces and programs {{site.prodname}} profiles.
1. serviceaccount controller: watches service accounts and programs {{site.prodname}} profiles.
1. workloadendpoint controller: watches for changes to pod labels and updates {{site.prodname}} workload endpoints.
1. node controller: watches for the removal of Kubernetes nodes and removes corresponding data from {{site.prodname}}.

The {{site.prodname}} Kubernetes manifests run these controllers within a single pod in the `calico-kube-controllers` deployment.

### Configuring datastore access

The datastore type can be configured via the `DATASTORE_TYPE` environment variable. Supported values are `etcdv3` and `kubernetes`.

#### etcdv3

The {{site.prodname}} Kubernetes controllers support the following environment variables to configure etcd access:

| Environment         | Description | Schema |
| ------------------- | ----------- | ------ |
| `ETCD_ENDPOINTS`    | Comma-delimited list of etcd endpoints to connect to. Example: `http://10.0.0.1:2379,http://10.0.0.2:2379`.
| `ETCD_CA_CERT_FILE` | Path to the file containing the root certificate of the CA that issued the etcd server certificate. Configures the Kubernetes controllers to trust the signature on the certificates provided by the etcd server. To disable authentication of the server by the Kubernetes controllers, set the value to `none`. | path
| `ETCD_CERT_FILE`    | Path to the file containing the client certificate issued to the Kubernetes controllers. Enables the Kubernetes controllers to participate in mutual TLS authentication and identify themselves to the etcd server. Example: `/etc/kube-controllers/cert.pem` | path
| `ETCD_KEY_FILE`     | Path to the file containing the private key of the Kubernetes controllers' client certificate. Enables the Kubernetes controllers to participate in mutual TLS authentication and identify themselves to the etcd server. Example: `/etc/kube-controllers/key.pem` | path

The `*_FILE` variables are _paths_ to the corresponding certificates/keys. As such, when the controllers are running as a Kubernetes pod, you
must ensure that the files exist within the pod. This is usually done in one of two ways:

* Mount the certificates from the host. This requires that the certificates be present on the host running the controller.
* Use Kubernetes [Secrets](http://kubernetes.io/docs/user-guide/secrets/) to mount the certificates into the pod as files.

#### kubernetes

When running the controllers as a Kubernetes pod, Kubernetes API access is [configured automatically][in-cluster-config] and
no additional configuration is required. However, the controllers can also be configured to use an explicit [kubeconfig][kubeconfig] file override to
configure API access if needed.

| Environment     | Description                                                        | Schema |
|-----------------|--------------------------------------------------------------------|--------|
| `KUBECONFIG`    | Path to a Kubernetes kubeconfig file mounted within the container. | path   |

### Other configuration

The following environment variables can be used to configure the {{site.prodname}} Kubernetes controllers.

| Environment   | Description | Schema | Default |
| ------------- | ----------- | ------ | -------
| `DATASTORE_TYPE`      | Which datastore type to use | etcdv3, kubernetes | etcdv3
| `ENABLED_CONTROLLERS` | Which controllers to run    | namespace, node, policy, serviceaccount, workloadendpoint | policy,namespace,serviceaccount,workloadendpoint,node
| `LOG_LEVEL`           | Minimum log level to be displayed. | debug, info, warning, error | info
| `KUBECONFIG`          | Path to a kubeconfig file for Kubernetes API access | path |
| `SYNC_NODE_LABELS`    | When enabled, Kubernetes node labels will be copied to Calico node objects. | boolean | true

## About each controller

### Node controller

The node controller automatically cleans up configuration for nodes that no longer exist. The controller must have read
access to the Kubernetes API to monitor `Node` events.

The node controller is not enabled by default if `ENABLED_CONTROLLERS` is not explicitly specified.
However, the {{site.prodname}} Kubernetes manifests explicitly specify the `ENABLED_CONTROLLERS` and enable this controller
within the calico-kube-controllers deployment.

This controller is valid when using either the `etcdv3` or `kubernetes` datastore types.

#### etcdv3

To enable the node controller when using `etcdv3`, perform the following two steps.

1. Add "node" to the list of enabled controllers in the environment for kube-controllers. For example: `ENABLED_CONTROLLERS=workloadendpoint,profile,policy,node`
1. Configure {{site.nodecontainer}} with a Kubernetes node reference by adding the following snippet to the environment section of the {{site.noderunning}} daemon set.
   ```
   - name: CALICO_K8S_NODE_REF
     valueFrom:
       fieldRef:
         fieldPath: spec.nodeName
   ```

Set `SYNC_NODE_LABELS` to true (enabled by default) to ensure that labels on
Kubernetes node resources remain in-sync with labels on the corresponding {{site.prodname}}
node resource. If both node resources specify a label with different values,
the Kubernetes node resource takes precedence. Labels on the {{site.prodname}}
resource that don't exist in the Kubernetes node will remain as is.

#### kubernetes

To enable the node controller when using `kubernetes`, set the list of enabled controllers
in the environment for kube-controllers to `node`. For example: `ENABLED_CONTROLLERS=node`

### Policy controller

The policy controller syncs Kubernetes network policies to the {{site.prodname}} datastore. The controller must have read
access to the Kubernetes API to monitor `NetworkPolicy` events.

The policy controller is enabled by default if `ENABLED_CONTROLLERS` is not explicitly specified.

This controller is only valid when using etcd as the {{site.prodname}} datastore.

### Workload endpoint controller

The workload endpoint controller automatically syncs Kubernetes pod label changes to the {{site.prodname}} datastore by updating
the corresponding workload endpoints appropriately. The controller must have read
access to the Kubernetes API to monitor `Pod` events.

The workload endpoint controller is enabled by default if `ENABLED_CONTROLLERS` is not explicitly specified.

This controller is only valid when using etcd as the {{site.prodname}} datastore.

### Namespace controller

The namespace controller syncs Kubernetes namespace label changes to the {{site.prodname}} datastore. The controller must have read
access to the Kubernetes API to monitor `Namespace` events.

The namespace controller is enabled by default if `ENABLED_CONTROLLERS` is not explicitly specified.

This controller is only valid when using etcd as the {{site.prodname}} datastore.

### Service account controller

The service account controller syncs Kubernetes service account changes to the {{site.prodname}} datastore.
The controller must have read access to the Kubernetes API to monitor `ServiceAccount` events.

The service account controller is enabled by default if `ENABLED_CONTROLLERS` is not explicitly specified.

This controller is only valid when using etcd as the {{site.prodname}} datastore.

[in-cluster-config]: https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/#accessing-the-api-from-a-pod
[kubeconfig]: https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/
