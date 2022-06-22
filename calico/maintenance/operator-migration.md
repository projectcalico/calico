---
title: Migrate Calico to an operator-managed installation
description: Migrate Calico from manifest-based to operator-managed installation
canonical_url: '/maintenance/operator-migration'
---

### Big picture

Switch your {{site.prodname}} installation from manifest-based resources to an installation managed by the {{site.prodname}} operator.

### Value

The {{site.prodname}} operator provides a number of advantages over traditional manifest-based installation of {{site.prodname}} resources, including but not limited to:

- Automatic platform and configuration detection.
- A simplified upgrade procedure.
- Well-defined split between end-user configuration and product code.
- Resource reconciliation and lifecycle management.

### Concepts

#### Operator vs manifest based installations

Most {{site.prodname}} installations in the past have been manifest-based, meaning that {{site.prodname}} is installed directly as a set of Kubernetes resources in a `.yaml` file.

The {{site.prodname}} operator is a Kubernetes application that installs and manages the lifecycle of a {{site.prodname}} installation by creating and updating Kubernetes resources 
such as Deployments, DaemonSets, Secrets, without the need for direct user intervention.

There are a few key differences to be aware of, if you are familiar with manifest-based installs and are looking to use the operator:

- {{site.prodname}} resources will be migrated from the `kube-system` namespace used by the {{site.prodname}} manifests to a new `calico-system` namespace.
- {{site.prodname}} resources will no longer be hand-editable, as the {{site.prodname}} operator will reconcile undesired changes in order to maintain an expected state.
- {{site.prodname}} resources can instead be configured via the `operator.tigera.io` APIs.

#### Operator migration

For new clusters, you can simply follow the steps in the [quickstart guide]({{site.baseurl}}/getting-started/kubernetes/quickstart) to get started with the operator.

For existing clusters using the `calico.yaml` manifest to install {{site.prodname}}, upon installing the operator, it will detect the existing {{site.prodname}} resources on the cluster
and calculate how to take ownership of them. The operator will maintain existing customizations, if supported, and warn about any unsupported configurations that it detects.

### Before you begin

- Ensure that your {{site.prodname}} installation is configured to use the Kubernetes datastore. If your cluster uses etcdv3 directly, you must follow [the datastore migration procedure]({{site.baseurl}}/maintenance/datastore-migration) before following this document.

### How To

#### Migrate a cluster to the operator 

> **Note**: Do not edit or delete any resources in the `kube-system` Namespace during the following procedure as it may interfere with the upgrade.
{: .alert .alert-warning}

1. Install the Tigera {{site.prodname}} operator and custom resource definitions.

   ```
   kubectl create -f {{site.data.versions.first.manifests_url}}/manifests/tigera-operator.yaml
   ```

1. Trigger the operator to start a migration by creating an `Installation` resource. The operator will auto-detect your existing {{site.prodname}} settings and fill out the spec section.

   ```
   kubectl create -f - <<EOF
   apiVersion: operator.tigera.io/v1
   kind: Installation
   metadata:
     name: default
   spec: {}
   EOF
   ```

1. Monitor the migration status with the following command:

   ```
   kubectl describe tigerastatus calico
   ```

1. Now that the migration is complete, you will see {{site.prodname}} resources have moved to the `calico-system` namespace.

   ```
   kubectl get pods -n calico-system
   ```

   You should see output like this:

   ```
   NAME                                       READY   STATUS    RESTARTS   AGE
   calico-kube-controllers-7688765788-9rqht   1/1     Running   0          17m
   calico-node-4ljs6                          1/1     Running   0          14m
   calico-node-bd8mc                          1/1     Running   0          14m
   calico-node-cpbd8                          1/1     Running   0          14m
   calico-node-jl97q                          1/1     Running   0          14m
   calico-node-xw2nj                          1/1     Running   0          14m
   calico-typha-57bf79f96f-6sk8x              1/1     Running   0          14m
   calico-typha-57bf79f96f-g99s9              1/1     Running   0          14m
   calico-typha-57bf79f96f-qtchs              1/1     Running   0          14m
   ```

   At this point, the operator will have automatically cleaned up any {{site.prodname}} resources in the `kube-system` namespace. No manual cleanup is required.
