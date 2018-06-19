---
title: Upgrading Calico for Kubernetes
sitemap: false 
canonical_url: 'https://docs.projectcalico.org/v3.1/getting-started/kubernetes/upgrade/'
---

This document covers upgrading the Calico components in a Kubernetes deployment.  This
upgrade procedure is supported for Calico v1.6+.

It is possible to upgrade the Calico components on a single node without affecting connectivity or
network policy for any existing pods.  However, it is recommended that you do not deploy
new pods to a node that is being upgraded.

It is recommended to upgrade one node at a time, rendering each node as
unschedulable using [kubectl cordon](http://kubernetes.io/docs/user-guide/kubectl/v1.8/#cordon)
before upgrading the node, and then make the node schedulable after the upgrade is
complete using [kubectl uncordon](http://kubernetes.io/docs/user-guide/kubectl/v1.8/#uncordon).

> **NOTE**
>
> When upgrading to etcd v3, as long as the cluster is migrated with the
`etcdctl migrate` command, the v2 data will remain untouched and the etcd v3
server will continue to speak the v2 protocol so the upgrade should have no
impact on Calico.

> **NOTE**
>
> When upgrading Calico using the Kubernetes datastore driver from a version < v2.3.0
> to a version >= v2.3.0, or when upgrading Calico using the etcd datastore from a version < v2.4.0
> to a version >= v2.4.0, you should follow the steps for [upgrading to v1 NetworkPolicy semantics](#upgrading-to-v1-networkpolicy-semantics)

> **Important**: If you are using the Kubernetes datastore and upgrading from 
> Calico v2.4.x or earlier to Calico v2.5.x or later, you must 
> [migrate your Calico configuration data](https://github.com/projectcalico/calico/blob/master/upgrade/v2.5/README.md) 
> before upgrading. Otherwise, your cluster may lose connectivity after the upgrade.
{: .alert .alert-danger}


## Upgrading a Hosted Installation of Calico

This section covers upgrading a [self-hosted]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted) Calico installation.

Note that while a self-hosted installation of Calico is typically done all at once (via calico.yaml), it is
recommended to perform upgrades one component at a time.

#### Upgrading the Calico policy controller

In a self-hosted Calico installation, the calico/kube-policy-controller is run under a Deployment.  As such,
it can be upgraded via the standard [Deployment mechanism](http://kubernetes.io/docs/user-guide/deployments/#updating-a-deployment).

To upgrade the policy controller, simply apply changes to the Deployment specification and Kubernetes will
do the rest.

```
kubectl apply -f policy-controller.yaml
```

> **NOTE**
>
> The Deployment must use `.spec.strategy.type==Recreate` to ensure that at most one instance of the
controller is running at a time.

##### Upgrading from pre-2.0

_Some earlier versions of the calico/kube-policy-controller were deployed as a ReplicaSet rather than a Deployment.
To upgrade from the ReplicaSet to a Deployment, follow these steps:_

- _Scale the existing ReplicaSet to 0 replicas_

```
kubectl scale rs -n kube-system calico-policy-controller --replicas=0
```

- _Deploy the new policy controller as a Deployment_

```
kubectl apply -f policy-controller.yaml
```

#### Upgrading the Calico DaemonSet

Upgrading the CNI plugin or calico/node image is done through a DaemonSet.  DaemonSets do not
currently support an update operation, and as such must be updated manually.

To upgrade the DaemonSet:

##### 1. Apply changes to the existing DaemonSet via kubectl apply.

Modify the DaemonSet manifest and run:

```
kubectl apply -f calico-node.yaml
```

> Alternatively, you can use `kubectl edit` to modify the DaemonSet.

##### 2. Upgrade each node.

Perform the following steps on each node one at a time.

First make the node unschedulable:

```
kubectl cordon node-01
```

Delete the calico-node pod running on the cordoned node and wait for the
DaemonSet controller to deploy a replacement.

```
kubectl delete pod -n kube-system calico-node-ajzy6e3t
```

Once the new calico-node Pod has started, make the node schedulable again.

```
kubectl uncordon node-01
```

> **NOTE**
>
> You may want to pre-fetch new Docker image to ensure the new node image is started
within BIRD's graceful restart period of 90 seconds.

#### Updating the Calico ConfigMap

Most self-hosted Calico deployments use a ConfigMap for configuration of the Calico
components.

To update the ConfigMap, make any desired changes and apply the new ConfigMap using
kubectl.  You will need to restart the policy controller and each calico/node instance
as described above before new config is reflected.

## Upgrading Components Individually

This section covers upgrading each component individually for use with custom configuration
management tools.

#### Upgrading the calico/node container

The calico/node container runs on each node in a Kubernetes cluster.  It runs Felix for policy
enforcement and BIRD for BGP networking (when enabled).

To upgrade the calico/node container:

- Pull the new version of the calico/node image to each node.  e.g `docker pull quay.io/calico/node:vA.B.C`
- Update the image in your process management to reference the new version.
- Stop the running calico/node container, and start it with the newly pulled version.

#### Upgrading the Calico CNI plugins

The Calico CNI plugins (calico and calico-ipam) are typically installed in /opt/cni/bin, though
this can vary based on deployment.

To upgrade the plugins, simply remove the existing binaries and replace them with the desired version.

To upgrade the CNI config (typically located in /etc/cni/net.d) simply make the desired changes to the
config file.  It will be picked up by the kubelet automatically for Kubernetes v1.4.0+.  For older versions
of Kubernetes you must restart the kubelet for changes to be applied.

#### Upgrading the Calico Policy Controller

The calico/kube-policy-controller can be stopped and restarted without affecting connectivity or
policy on existing pods.  New pods in existing Namespaces will correctly have
existing policy applied even when the controller is not running.  However, when the
policy controller is not running:

- New NetworkPolicies will not be applied.
- New Pods in new Namespaces will not get network connectivity.
- Label changes to existing pods will not be reflected in the applied policy.

> **NOTE**
>
> Only one instance of the controller should ever be active at a time.

To upgrade the policy controller:

- Pull the new version of the calico/kube-policy-controller image to each node.
- Update the image in your process management to reference the new version.
- Stop the running container, and start it with the newly pulled version.

We recommend running the policy controller as a Kubernetes Deployment with type "recreate", in which
case upgrade can be handled entirely through the
standard [Deployment mechanism](http://kubernetes.io/docs/user-guide/deployments/#updating-a-deployment)

## Upgrading to v1 NetworkPolicy semantics

Calico v2.3.0 (when using the Kubernetes datastore driver) and Calico v2.4.0 (when using the etcd datastore driver)
interpret the Kubernetes `NetworkPolicy` differently than previous releases, as specified
in [upstream Kubernetes](https://github.com/kubernetes/kubernetes/pull/39164#issue-197243974).

To maintain behavior when upgrading, you should follow these steps prior to upgrading Calico to ensure your configured policy is
enforced consistently throughout the upgrade process.

- In any Namespace that previously did _not_ have a "DefaultDeny" annotation:
  - Delete any NetworkPolicy objects in that Namespace.  After upgrade, these policies will become active and may block traffic that was previously allowed.
- In any Namespace that previously had a "DefaultDeny" annotation:
  - Create a NetworkPolicy which matches all pods but does not allow any traffic.  After upgrade, the Namespace annotation will have no effect, but this empty NetworkPolicy will provide the same behavior.

Here is an example of a NetworkPolicy which selects all pods in the Namespace, but does not allow any traffic:

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny
spec:
  podSelector:
```

> **Note**:
>
> The above steps should be followed when upgrading to Calico v2.3.0+ using the Kubernetes
> datastore driver, and Calico v2.4.0+ using the etcd datastore,
> independent of the Kubernetes version being used.
