---
title: Kubernetes controllers configuration
description: API for KubeControllersConfiguration resource.
canonical_url: '/reference/resources/kubecontrollersconfig'
---

A {{site.prodname}} [Kubernetes controllers]({{ site.baseurl }}/reference/kube-controllers/configuration) configuration resource (`KubeControllersConfiguration`) represents configuration options for the {{site.prodname}} Kubernetes controllers.

### Sample YAML

```yaml
apiVersion: projectcalico.org/v3
kind: KubeControllersConfiguration
metadata:
  name: default
spec:
  logSeverityScreen: Info
  healthChecks: Enabled
  etcdv3CompactionPeriod: 10m
  prometheusMetricsPort: 9094
  controllers:
    node:
      reconcilerPeriod: 5m
      leakGracePeriod: 15m
      syncLabels: Enabled
      hostEndpoint:
        autoCreate: Disabled
    policy:
      reconcilerPeriod: 5m
    workloadEndpoint:
      reconcilerPeriod: 5m
    serviceAccount:
      reconcilerPeriod: 5m
    namespace:
      reconcilerPeriod: 5m
```

### Kubernetes controllers configuration definition

#### Metadata

| Field | Description                                               | Accepted Values   | Schema |
|-------|-----------------------------------------------------------|-------------------|--------|
| name  | Unique name to describe this resource instance. Required. | Must be `default` | string |

- {{site.prodname}} automatically creates a resource named `default` containing the configuration settings, only the name `default` is used and only one object of this type is allowed. You can use [calicoctl]({{ site.baseurl }}/reference/calicoctl/overview) to view and edit these settings

#### Spec

| Field                  | Description                                               | Accepted Values                    | Schema | Default    |
|------------------------|-----------------------------------------------------------|------------------------------------|--------|------------|
| logSeverityScreen      | The log severity above which logs are sent to the stdout. | Debug, Info, Warning, Error, Fatal | string | Info       |
| healthChecks           | Enable support for health checks                          | Enabled, Disabled                  | string | Enabled    |
| prometheusMetricsPort  | Port on which to serve prometheus metrics.                | Set to 0 to disable, > 0 to enable. | TCP port | 9094 |
| etcdv3CompactionPeriod | The period between etcdv3 compaction requests. Only applies when using etcd as the {{site.prodname}} datastore. | Set to 0 to disable, > 0 to enable |  [Duration string][parse-duration] | 10m |
| controllers            | Enabled controllers and their settings                    |                                    | [Controllers](#controllers) | |

#### Controllers

| Field            | Description                                           |  Schema                                        |
|------------------|-------------------------------------------------------|------------------------------------------------|
| node             | Enable and configure the node controller              | omit to disable, or [NodeController](#nodecontroller) |
| policy           | Enable and configure the network policy controller    | omit to disable, or [PolicyController](#policycontroller)           |
| workloadEndpoint | Enable and configure the workload endpoint controller | omit to disable, or [WorkloadEndpointController](#workloadendpointcontroller) |
| serviceAccout    | Enable and configure the service account controller   | omit to disable, or [ServiceAccountController](#serviceaccountcontroller)  |
| namespace        | Enable and configure the namespace controller         | omit to disable, or [NamespaceController](#namespacecontroller)        |

#### NodeController

The node controller automatically cleans up configuration for nodes that no longer exist. Optionally, it can create host endpoints for all Kubernetes nodes.

| Field                              | Description                 | Accepted Values   | Schema | Default    |
|------------------------------------|-----------------------------|-------------------|--------|------------|
| reconcilerPeriod | Period to perform reconciliation with the {{site.prodname}} datastore | | [Duration string][parse-duration] | 5m |
| syncLabels | When enabled, Kubernetes node labels will be copied to {{site.prodname}} node objects. | Enabled, Disabled | string | Enabled |
| hostEndpoint | Controls allocation of host endpoints | | [HostEndpoint](#hostendpoint) | |
| leakGracePeriod | Grace period to use when garbage collecting suspected leaked IP addresses. | | [Duration string][parse-duration] | 15m |

#### HostEndpoint

| Field      | Description                                                      | Accepted Values   | Schema | Default    |
|------------|------------------------------------------------------------------|-------------------|--------|------------|
| autoCreate | When enabled, automatically create a host endpoint for each node | Enabled, Disabled | string | Disabled   |

#### PolicyController

The policy controller syncs Kubernetes network policies to the Calico datastore.  This controller is only valid when using etcd as the {{site.prodname}} datastore.

| Field            | Description                                                           | Schema                            | Default |
|------------------|-----------------------------------------------------------------------|-----------------------------------|---------|
| reconcilerPeriod | Period to perform reconciliation with the {{site.prodname}} datastore | [Duration string][parse-duration] | 5m      |

#### WorkloadEndpointController

The workload endpoint controller automatically syncs Kubernetes pod label changes to the {{site.prodname}} datastore by updating the corresponding workload
endpoints appropriately.  This controller is only valid when using etcd as the {{site.prodname}} datastore.

| Field            | Description                                                           | Schema                            | Default |
|------------------|-----------------------------------------------------------------------|-----------------------------------|---------|
| reconcilerPeriod | Period to perform reconciliation with the {{site.prodname}} datastore | [Duration string][parse-duration] | 5m      |

#### ServiceAccountController

The service account controller syncs Kubernetes service account changes to the {{site.prodname}} datastore.  This controller is only valid when using etcd as
the {{site.prodname}} datastore.

| Field            | Description                                                           | Schema                            | Default |
|------------------|-----------------------------------------------------------------------|-----------------------------------|---------|
| reconcilerPeriod | Period to perform reconciliation with the {{site.prodname}} datastore | [Duration string][parse-duration] | 5m      |

#### NamespaceController

The namespace controller syncs Kubernetes namespace label changes to the {{site.prodname}} datastore. This controller is only valid when using etcd as the
{{site.prodname}} datastore.

| Field            | Description                                                           | Schema                            | Default |
|------------------|-----------------------------------------------------------------------|-----------------------------------|---------|
| reconcilerPeriod | Period to perform reconciliation with the {{site.prodname}} datastore | [Duration string][parse-duration] | 5m      |

### Supported operations

| Datastore type        | Create  | Delete (Global `default`)  |  Update  | Get/List | Notes
|-----------------------|---------|----------------------------|----------|----------|------
| etcdv3                | Yes     | Yes                        | Yes      | Yes      |
| Kubernetes API server | Yes     | Yes                        | Yes      | Yes      |

[parse-duration]: https://golang.org/pkg/time/#ParseDuration
