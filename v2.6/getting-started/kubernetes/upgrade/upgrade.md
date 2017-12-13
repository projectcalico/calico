---
title: Upgrading Calico components
redirect_from: latest/getting-started/kubernetes/upgrade
---

It is possible to upgrade the {{side.prodname}} components on a single node without affecting connectivity or
network policy for any existing pods.  However, it is recommended that you do not deploy
new pods to a node that is being upgraded.

It is recommended to upgrade one node at a time, rendering each node as
unschedulable using [kubectl cordon](http://kubernetes.io/docs/user-guide/kubectl/v1.8/#cordon)
before upgrading the node, and then make the node schedulable after the upgrade is
complete using [kubectl uncordon](http://kubernetes.io/docs/user-guide/kubectl/v1.8/#uncordon).

## Upgrading a Hosted Installation of {{side.prodname}}

This section covers upgrading a [self-hosted](/{{page.version}}/getting-started/kubernetes/installation/hosted) {{side.prodname}} installation.

Note that while a self-hosted installation of {{side.prodname}} is typically done all 
at once (via calico.yaml), it is recommended to perform upgrades one component at a time.

#### Upgrading the {{side.prodname}} Kubernetes controllers

In a self-hosted {{side.prodname}} installation, the calico/kube-controllers container 
is run as a deployment.  As such, it can be upgraded via the standard [deployment mechanism](http://kubernetes.io/docs/user-guide/deployments/#updating-a-deployment).

To upgrade the controllers, simply apply changes to the deployment specification and Kubernetes will
do the rest.

```
kubectl apply -f new-controllers.yaml
```

> **Note**: The deployment must use `.spec.strategy.type==Recreate` to
> ensure that at most one instance of the controller is running at a time.
{: .alert .alert-info}


#### Upgrading the {{side.prodname}} DaemonSet

Upgrading the CNI plugin or calico/node image is done through a DaemonSet.  DaemonSets do not
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

Delete the calico-node pod running on the cordoned node and wait for the
DaemonSet controller to deploy a replacement.

```
kubectl delete pod -n kube-system calico-node-ajzy6e3t
```

Once the new calico-node Pod has started, make the node schedulable again.

```
kubectl uncordon node-01
```


> **Note**: You may want to pre-fetch the new Docker image to ensure the new
> node image is started within BIRD's graceful restart period of 90 seconds.
{: .alert .alert-info}


#### Updating the {{side.prodname}} ConfigMap

Most self-hosted {{side.prodname}} deployments use a ConfigMap for configuration 
of the {{side.prodname}} components.

To update the ConfigMap, make any desired changes and apply the new ConfigMap using
kubectl.  You will need to restart the {{side.prodname}} Kubernetes controllers and 
each calico/node instance as described above before new config is reflected.

## Upgrading Components Individually

This section covers upgrading each component individually for use with custom 
configuration management tools.

#### Upgrading the calico/node container

The calico/node container runs on each node in a Kubernetes cluster.  It runs Felix for policy
enforcement and BIRD for BGP networking (when enabled).

To upgrade the calico/node container:

1. Pull the new version of the calico/node image to each node.  

   ```
   docker pull {{site.imageNames["calico-node"]}}:{{site.data.versions[page.version].first.title}}
   ```

1. Update the image in your process management to reference the new version.

1. Stop the running calico/node container, and start it with the newly pulled version.

#### Upgrading the {{side.prodname}} CNI plugins

The {{side.prodname}} CNI plugins (calico and calico-ipam) are typically installed in /opt/cni/bin, though
this can vary based on deployment.

To upgrade the plugins, simply remove the existing binaries and replace them with the desired version.

To upgrade the CNI config (typically located in /etc/cni/net.d) simply make the desired changes to the
config file.  It will be picked up by the kubelet automatically for Kubernetes v1.4.0+.  For older versions
of Kubernetes you must restart the kubelet for changes to be applied.

#### Upgrading the {{side.prodname}} Kubernetes controllers

The calico/kube-controllers pod can be stopped and restarted without affecting connectivity or
policy on existing pods.  New pods in existing namespaces will correctly have
existing policy applied even when the controller is not running.  However, when the
controllers are not running:

- New `NetworkPolicy` resources will not be applied.
- New pods in new namespaces will not get network connectivity.
- Label changes to existing pods will not be reflected in the applied policy.


> **Note**: Only one instance of the controller should ever be active at a time.
{: .alert .alert-info}

To upgrade the controllers:

- Pull the new version of the calico/kube-controllers image to each node.
- Update the image in your process management to reference the new version.
- Stop the running container, and start it with the newly pulled version.

We recommend running the controllers as a Kubernetes deployment with type "recreate", in which
case upgrade can be handled entirely through the
standard [deployment mechanism](http://kubernetes.io/docs/user-guide/deployments/#updating-a-deployment)

