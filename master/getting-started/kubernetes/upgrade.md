---
title: Upgrading Calico for Kubernetes
---

This document covers upgrading {{site.prodname}} in a Kubernetes deployment.  This
upgrade procedure is supported for Calico v1.6+.

It is possible to upgrade {{site.prodname}} on a single node without affecting connectivity or
network policy for any existing pods.  However, it is recommended that you do not deploy
new pods to a node that is being upgraded.

It is recommended to upgrade one node at a time, rendering each node as
unschedulable using [kubectl cordon](http://kubernetes.io/docs/user-guide/kubectl/v1.8/#cordon)
before upgrading the node, and then make the node schedulable after the upgrade is
complete using [kubectl uncordon](http://kubernetes.io/docs/user-guide/kubectl/v1.8/#uncordon).

> **Note**: When upgrading to etcd v3, as long as the cluster is migrated with the
`etcdctl migrate` command, the v2 data will remain untouched and the etcd v3
server will continue to speak the v2 protocol so the upgrade should have no
impact on {{site.prodname}}.
{: .alert .alert-info}

> **Note**: When upgrading {{site.prodname}} using the Kubernetes datastore driver from a version < v2.3.0
> to a version >= v2.3.0, or when upgrading {{site.prodname}} using the etcd datastore from a version < v2.4.0
> to a version >= v2.4.0, you should follow the steps for
> [upgrading to v1 NetworkPolicy semantics](#upgrading-to-v1-networkpolicy-semantics)
{: .alert .alert-info}

> **Important**: If you are using the Kubernetes datastore and upgrading from
> Calico v2.4.x or earlier to Calico v2.5.x or later, you must
> [migrate your {{site.prodname}} configuration data](https://github.com/projectcalico/calico/blob/master/upgrade/v2.5/README.md)
> before upgrading. Otherwise, your cluster may lose connectivity after the upgrade.
{: .alert .alert-danger}


## Upgrading a Hosted Installation of {{site.prodname}}

This section covers upgrading a [self-hosted]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation/hosted) {{site.prodname}} installation.

Note that while a self-hosted installation of {{site.prodname}} is typically done all at once (via calico.yaml), it is
recommended to perform upgrades one component at a time.

#### Upgrading the Kubernetes controllers

In a self-hosted {{site.prodname}} installation, the `calico/kube-controllers` container is run as a deployment.  As such,
it can be upgraded via the standard [deployment mechanism](http://kubernetes.io/docs/user-guide/deployments/#updating-a-deployment).

To upgrade the controllers, simply apply changes to the deployment specification and Kubernetes will
do the rest.

```
kubectl apply -f new-controllers.yaml
```

> **Note**: The deployment must use `.spec.strategy.type==Recreate` to
> ensure that at most one instance of the controller is running at a time.
{: .alert .alert-info}


#### Upgrading the DaemonSet

Upgrading the CNI plugin or `{{site.nodecontainer}}` image is done through a DaemonSet.  DaemonSets do not
currently support an update operation, and as such must be updated manually.

To upgrade the DaemonSet:

##### 1. Apply changes to the existing DaemonSet via kubectl apply.

Modify the DaemonSet manifest and run:

```
kubectl apply -f calico-node.yaml
```

> **Note**: Alternatively, you can use `kubectl edit` to modify the DaemonSet.
{: .alert .alert-info}


##### 2. Upgrade each node.

Perform the following steps on each node one at a time.

First make the node unschedulable:

```
kubectl cordon node-01
```

Delete the `{{site.noderunning}}` pod running on the cordoned node and wait for the
DaemonSet controller to deploy a replacement.

```
kubectl delete pod -n kube-system {{site.noderunning}}-ajzy6e3t
```

Once the new `{{site.noderunning}}` pod has started, make the node schedulable again.


```
kubectl uncordon node-01
```


> **Note**: You may want to pre-fetch the new Docker image to ensure the new
> node image is started within BIRD's graceful restart period of 90 seconds.
{: .alert .alert-info}


#### Updating the {{site.prodname}} ConfigMap

Most self-hosted {{site.prodname}} deployments use a ConfigMap for configuration of the {{site.prodname}}
components.

To update the ConfigMap, make any desired changes and apply the new ConfigMap using
kubectl.  You will need to restart the {{site.prodname}} Kubernetes controllers and each `{{site.nodecontainer}}` instance
as described above before new config is reflected.

## Upgrading components individually

This section covers upgrading each component individually for use with custom configuration
management tools.

#### Upgrading the {{site.nodecontainer}} container

The `{{site.nodecontainer}}` container runs on each node in a Kubernetes cluster.  It runs Felix for policy
enforcement and BIRD for BGP networking (when enabled).

To upgrade the `{{site.nodecontainer}}` container:

- Pull the new version of the `{{site.nodecontainer}}` image to each node. For example: `docker pull {{site.imageNames["node"]}}:{{site.data.versions[page.version].first.title}}`.
- Update the image in your process management to reference the new version.
- Stop the running `{{site.noderunning}}` container, and start it with the newly pulled version.

#### Upgrading the CNI plugins

The CNI plugins (`calico` and `calico-ipam`) are typically installed in /opt/cni/bin, though
this can vary based on deployment.

To upgrade the plugins, simply remove the existing binaries and replace them with the desired version.

To upgrade the CNI config (typically located in /etc/cni/net.d) simply make the desired changes to the
config file.  It will be picked up by the kubelet automatically for Kubernetes v1.4.0+.  For older versions
of Kubernetes you must restart the kubelet for changes to be applied.

#### Upgrading the Kubernetes controllers

The `calico/kube-controllers` pod can be stopped and restarted without affecting connectivity or
policy on existing pods.  New pods in existing namespaces will correctly have
existing policy applied even when the controller is not running.  However, when the
controllers are not running:

- New network policies will not be applied.
- New pods in new namespaces will not get network connectivity.
- Label changes to existing pods will not be reflected in the applied policy.


> **Note**: Only one instance of the controller should ever be active at a time.
{: .alert .alert-info}

To upgrade the controllers:

- Pull the new version of the `calico/kube-controllers` image to each node.
- Update the image in your process management to reference the new version.
- Stop the running container, and start it with the newly pulled version.

We recommend running the controllers as a Kubernetes deployment with type "recreate", in which
case upgrade can be handled entirely through the
standard [deployment mechanism](http://kubernetes.io/docs/user-guide/deployments/#updating-a-deployment)

## Upgrading to v1 NetworkPolicy semantics

Calico v2.3.0 (when using the Kubernetes datastore driver) and Calico v2.4.0 (when using the etcd datastore driver)
interpret the Kubernetes `NetworkPolicy` differently than previous releases, as specified
in [upstream Kubernetes](https://github.com/kubernetes/kubernetes/pull/39164#issue-197243974).

To maintain behavior when upgrading, you should follow these steps prior to upgrading {{site.prodname}} to ensure your configured policy is
enforced consistently throughout the upgrade process.

- In any namespace that previously did _not_ have a "DefaultDeny" annotation:
  - Delete any `NetworkPolicy` objects in that namespace.  After upgrade, these policies will become active and may block traffic that was previously allowed.
- In any namespace that previously had a "DefaultDeny" annotation:
  - Create a `NetworkPolicy` which matches all pods but does not allow any traffic.  After upgrade, the namespace annotation will have no effect, but this empty `NetworkPolicy` will provide the same behavior.

Here is an example of a `NetworkPolicy` which selects all pods in the namespace, but does not allow any traffic:

```yaml
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny
spec:
  podSelector:
```

> **Note**: The above steps should be followed when upgrading to
> Calico v2.3.0+ using the Kubernetes
> datastore driver, and Calico v2.4.0+ using the etcd datastore,
> independent of the Kubernetes version being used.
{: .alert .alert-info}
