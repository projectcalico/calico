---
title: Upgrading Calico for Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/kubernetes/upgrade/'
---

This document covers upgrading the Calico components in a Kubernetes deployment.  This
upgrade procedure is supported for Calico v1.6+.

It is possible to upgrade the Calico components on a single node without affecting connectivity or
network policy for any existing pods.  However, it is recommended that you do not deploy
new pods to a node that is being upgraded.

It is recommended to upgrade one node at a time, rendering each node as
unscheduleable using [kubectl cordon](http://kubernetes.io/docs/user-guide/kubectl/v1.6/#cordon)
before upgrading the node, and then make the node scheduleable after the upgrade is
complete using [kubectl uncordon](http://kubernetes.io/docs/user-guide/kubectl/v1.6/#uncordon).

> **NOTE**
>
> When upgrading to etcd v3, as long as the cluster is migrated with the
`etcdctl migrate` command, the v2 data will remain untouched and the etcd v3
server will continue to speak the v2 protocol so the upgrade should have no
impact on Calico.

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
