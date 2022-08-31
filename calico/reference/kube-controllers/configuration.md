---
title: Configuring the Calico Kubernetes controllers
description: Calico Kubernetes controllers monitor the Kubernetes API and perform actions based on cluster state.
---

The {{site.prodname}} Kubernetes controllers are deployed in a Kubernetes cluster. The different controllers monitor the Kubernetes API
and perform actions based on cluster state.

{% tabs %}
  <label:Operator,active:true>
<%

If you have installed Calico using the operator, see the [KubeControllersConfiguration](../resources/kubecontrollersconfig) resource instead.

%>

  <label:Manifest>
<%

The controllers are primarily configured through environment variables. When running
the controllers as a Kubernetes pod, this is accomplished through the pod manifest `env`
section.

## The {{page.imageNames["calico/kube-controllers"]}} container

The `{{page.imageNames["calico/kube-controllers"]}}` container includes the following controllers:

1. policy controller: watches network policies and programs {{site.prodname}} policies.
1. namespace controller: watches namespaces and programs {{site.prodname}} profiles.
1. serviceaccount controller: watches service accounts and programs {{site.prodname}} profiles.
1. workloadendpoint controller: watches for changes to pod labels and updates {{site.prodname}} workload endpoints.
1. node controller: watches for the removal of Kubernetes nodes and removes corresponding data from {{site.prodname}}, and optionally watches for node updates to create and sync host endpoints for each node.

The {{site.prodname}} Kubernetes manifests run these controllers within a single pod in the `calico-kube-controllers` deployment.

### Configuring datastore access

The datastore type can be configured via the `DATASTORE_TYPE` environment variable. Supported values are `etcdv3` and `kubernetes`.

#### etcdv3

The {{site.prodname}} Kubernetes controllers support the following environment variables to configure etcd access:

| Environment          | Description | Schema |
| -------------------- | ----------- | ------ |
| `ETCD_ENDPOINTS`     | Comma-delimited list of etcd endpoints to connect to. Example: `http://10.0.0.1:2379,http://10.0.0.2:2379`. | string
| `ETCD_DISCOVERY_SRV` | Domain name to discover etcd endpoints via SRV records. Mutually exclusive with `ETCD_ENDPOINTS`. Example: `example.com` | string
| `ETCD_CA_CERT_FILE`  | Path to the file containing the root certificate of the CA that issued the etcd server certificate. Configures the Kubernetes controllers to trust the signature on the certificates provided by the etcd server. To disable authentication of the server by the Kubernetes controllers, set the value to `none`. | path
| `ETCD_CERT_FILE`     | Path to the file containing the client certificate issued to the Kubernetes controllers. Enables the Kubernetes controllers to participate in mutual TLS authentication and identify themselves to the etcd server. Example: `/etc/kube-controllers/cert.pem` | path
| `ETCD_KEY_FILE`      | Path to the file containing the private key of the Kubernetes controllers' client certificate. Enables the Kubernetes controllers to participate in mutual TLS authentication and identify themselves to the etcd server. Example: `/etc/kube-controllers/key.pem` | path

The `*_FILE` variables are _paths_ to the corresponding certificates/keys. As such, when the controllers are running as a Kubernetes pod, you
must ensure that the files exist within the pod. This is usually done in one of two ways:

* Mount the certificates from the host. This requires that the certificates be present on the host running the controller.
* Use Kubernetes [Secrets](http://kubernetes.io/docs/user-guide/secrets/){:target="_blank"} to mount the certificates into the pod as files.

#### kubernetes

When running the controllers as a Kubernetes pod, Kubernetes API access is [configured automatically][in-cluster-config] and
no additional configuration is required. However, the controllers can also be configured to use an explicit [kubeconfig][kubeconfig] file override to
configure API access if needed.

| Environment     | Description                                                        | Schema |
|-----------------|--------------------------------------------------------------------|--------|
| `KUBECONFIG`    | Path to a Kubernetes kubeconfig file mounted within the container. | path   |

### Other configuration

> **Note:** Whenever possible, prefer configuring the kube-controllers component using the [KubeControllersConfiguration]({{site.baseurl}}/reference/resources/kubecontrollersconfig) API resource,
> Some configuration options may not be available through environment variables.
{: .alert .alert-info}

The following environment variables can be used to configure the {{site.prodname}} Kubernetes controllers.

| Environment   | Description | Schema | Default |
| ------------- | ----------- | ------ | -------
| `DATASTORE_TYPE`      | Which datastore type to use | etcdv3, kubernetes | kubernetes
| `ENABLED_CONTROLLERS` | Which controllers to run    | namespace, node, policy, serviceaccount, workloadendpoint | policy,namespace,serviceaccount,workloadendpoint,node
| `LOG_LEVEL`           | Minimum log level to be displayed. | debug, info, warning, error | info
| `KUBECONFIG`          | Path to a kubeconfig file for Kubernetes API access | path |
| `SYNC_NODE_LABELS`    | When enabled, Kubernetes node labels will be copied to Calico node objects. | boolean | true
| `AUTO_HOST_ENDPOINTS` | When set to enabled, automatically create a host endpoint for each node. | enabled, disabled | disabled
| `COMPACTION_PERIOD` | Compact the etcd database on this interval. Set to "0" to disable. | [duration](https://golang.org/pkg/time/#ParseDuration){:target="_blank"} | 10m

## About each controller

### Node controller

The node controller has several functions depending on the datastore in use.

**Either datastore**

- Garbage collects IP addresses.
- Automatically provisions host endpoints for Kubernetes nodes.

**etcdv3 only**

- Garbage collects projectcalico.org/v3 Node resources when the Kubernetes node is deleted.
- Synchronizes labels between Kubernetes and Calico Node resources.

The node controller is not enabled by default if `ENABLED_CONTROLLERS` is not explicitly specified.
However, the {{site.prodname}} Kubernetes manifests explicitly specify the `ENABLED_CONTROLLERS` and enable this controller
within the calico-kube-controllers deployment.

This controller is valid when using either the `etcdv3` or `kubernetes` datastore types.

#### etcdv3

To enable the node controller when using `etcdv3`, perform the following two steps.

1. Enable the controller in your [KubeControllersConfiguration]({{site.baseurl}}/reference/resources/kubecontrollersconfig) or add "node" to the list of enabled controllers in the environment for kube-controllers. For example: `ENABLED_CONTROLLERS=workloadendpoint,profile,policy,node`
1. Configure {{site.nodecontainer}} with a Kubernetes node reference by adding the following snippet to the environment section of the {{site.noderunning}} daemon set.

   ```yaml
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

To enable the node controller when using `kubernetes`, enable the controller in your [KubeControllersConfiguration]({{site.baseurl}}/reference/resources/kubecontrollersconfig) or set the list of enabled controllers in the environment for kube-controllers to `node`. For example: `ENABLED_CONTROLLERS=node`

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

%>
{% endtabs %}

[in-cluster-config]: https://kubernetes.io/docs/tasks/access-application-cluster/access-cluster/#accessing-the-api-from-a-pod
[kubeconfig]: https://kubernetes.io/docs/concepts/configuration/organize-cluster-access-kubeconfig/

