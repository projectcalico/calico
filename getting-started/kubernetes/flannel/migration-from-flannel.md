---
title: Migrate a cluster from flannel networking to Calico networking
description: Take advantage of the more flexible Calico IP address management by upgrading from flannel VXLAN to Calico VXLAN netowrking. 
---

### Big picture

Migrate an existing Kubernetes cluster with flannel VXLAN networking to Calico VXLAN networking.

### Value

Migrating from flannel networking to Calico networking lets you take advantage of Calico IP address management (IPAM) for more efficient and flexible managed of IP addresses.

To see all options for using flannel with Calico (including using Calico network policy), see [Blog: Live Migration from Flannel to Calico](https://www.projectcalico.org/live-migration-from-flannel-to-calico/).

### Concepts

#### Limitations of host-local IPAM in flannel

Flannel networking uses the host-local IPAM (IP address management) CNI plugin, which provides simple IP address management for your cluster. Although simple, it has limitations:

- When you create a node, it is pre-allocated a CIDR. If the number of pods per-node exceeds the number of IP addresses available per node, you must recreate the cluster. Conversely, if the number of pods is much smaller than the number of addresses available per node, IP address space is not efficiently used; as you scale out and IP addresses are depleted, inefficiencies become a pain point.

- Because each node has a pre-allocated CIDR, pods must always have an IP address assigned based on the node it is running on. Being able to allocate IP addresses based on other attributes (for example, the pod’s namespace), provides flexiblity to meet use cases that arise.

Migrating to Calico IPAM solves these use cases and more.

#### Methods for migrating to Calico networking

There are two ways to switch your cluster to use Calico networking. Both methods give you a fully-functional Calico cluster using VXLAN networking between pods.

- **Create a new cluster using Calico and migrate existing workloads**
  If you have the ability to migrate worloads from one cluster to the next without caring about downtime, this is the easiest method: [create a new cluster using Calico]({{site.baseurl}}/getting-started/kubernetes/quickstart).

- **Live migration on an existing cluster**
  If your workloads are already in production, or downtime is not an option, use the live migration tool that performs a rolling update of each node in the cluster. 

### Before you begin...

**Required**

- A cluster with flannel for networking using the VXLAN backend.
- Flannel version v0.9.1 or higher (Canal version v3.7.0 or greater).
- Flannel must have been installed using a **Kubernetes daemon set** and configured:
  - To use the Kubernetes API for storing its configuration (as opposed to etcd)
  - With `DirectRouting` disabled (default)
- Cluster must allow for:
  - Adding/deleting/modifying node labels
  - Modifying and deleting of the flannel daemon set. For example, it must not be installed using the Kubernetes Addon-manager.

### How to

- [Migrate from flannel networking to Calico networking, live migration](#migrate-from-flannel-networking-to-calico-networking-live-migration)
- [Modify flannel configuration](#modify-flannel-configuration)
- [View migration status](#view-migration-status)
- [View migration logs](#view-migration-logs)
- [Revert migration](#revert-migration)

#### Migrate from flannel networking to Calico networking, live migration

1. Install Calico.

   ```
   kubectl apply -f {{ "/manifests/flannel-migration/calico.yaml" | absolute_url }}
   ```

1. Start the migration controller.

   ```
   kubectl apply -f {{ "/manifests/flannel-migration/migration-job.yaml" | absolute_url }}
   ```

   You will see nodes begin to update one at a time.

1. Monitor the migration.

   ```
   kubectl get jobs -n kube-system flannel-migration
   ```

   When the host node is upgraded, the migration controller may be rescheduled several times. The installation is complete when the output of the above command shows 1/1 completions. For example:

   ```
   NAME                COMPLETIONS   DURATION   AGE
   flannel-migration   1/1           2m59s      5m9s
   ```

1. Delete the migration controller.

   ```
   kubectl delete -f {{ "/manifests/flannel-migration/migration-job.yaml" | absolute_url }}
   ```

#### Modify flannel configuration 

The migration controller autodetects your flannel configuration, and in most cases, does not require
additional configuration. If you require special configuration, the migration tool provides the following options,
which can be set as environment variables within the pod.

| Configuration options            | Description                                                          | Default                                    |
|----------------------------------|----------------------------------------------------------------------|--------------------------------------------|
| FLANNEL_NETWORK                  | IPv4 network CIDR used by flannel for the cluster.                   | Automatically detected                     |
| FLANNEL_DAEMONSET_NAME           | Name of the flannel daemon set in the kube-system namespace.         | kube-flannel-ds-amd64                      |
| FLANNEL_MTU                      | MTU for the flannel VXLAN device.                                    | Automatically detected                     |
| FLANNEL_IP_MASQ                  | Whether masquerading is enabled for outbound traffic.                | Automatically detected                     |
| FLANNEL_SUBNET_LEN               | Per-node subnet length used by flannel.                              | 24                                         |
| FLANNEL_ANNOTATION_PREFIX        | Value provided via the kube-annotation-prefix option to flannel.     |  flannel.alpha.coreos.com                  |
| FLANNEL_VNI                      | The VNI used for the flannel network.                                |  1                                         |
| FLANNEL_PORT                     | UDP port used for VXLAN.                                             |  8472                                      |
| CALICO_DAEMONSET_NAME            | Name of the calico daemon set in the kube-system namespace.          |  calico-node                               |
| CNI_CONFIG_DIR                   | Full path on the host in which to search for CNI config files.       |  /etc/cni/net.d                            |

#### View migration status

View the controller's current status.

```
kubectl get pods -n kube-system -l k8s-app=flannel-migration-controller
```

#### View migration logs

View migration logs to see if any actions are required.

```
kubectl logs -n kube-system -l k8s-app=flannel-migration-controller
```

#### Revert migration

If you need to revert a cluster from Calico back to flannel, follow these steps.


1. Remove the migration controller and Calico.

   ```
   kubectl delete -f {{ "/manifests/flannel-migration/migration-job.yaml" | absolute_url }}
   kubectl delete -f {{ "/manifests/flannel-migration/calico.yaml" | absolute_url }}
   ```

1. Determine the nodes that were migrated to Calico.

   ```
   kubectl get nodes -l projectcalico.org/node-network-during-migration=calico
   ```

Then, for each node found above, run the following commands to delete Calico.

1. Cordon and drain the node.

   ```
   kubectl drain <node name>
   ```

1. Log in to the node and remove the CNI configuration.

   ```
   rm /etc/cni/net.d/10-calico.conflist
   ```

1. Reboot the node.

1. Enable flannel on the node.

   ```
   kubectl label node <node name> projectcalico.org/node-network-during-migration=flannel --overwrite
   ```

1. Uncordon the node.

   ```
   kubectl uncordon <node name>
   ```

After the above steps have been completed on each node, perform the following steps.

1. Remove the `nodeSelector` from the flannel daemonset.

   ```
   kubectl patch ds/kube-flannel-ds-amd64 -n kube-system -p '{"spec": {"template": {"spec": {"nodeSelector": null}}}}'
   ```

1. Remove the migration label from all nodes.

   ```
   kubectl label node --all projectcalico.org/node-network-during-migration-
   ```

### Next steps

Learn about [Calico IP address management]({{site.baseurl}}/networking/ipam)
