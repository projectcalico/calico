---
title: Migrating a cluster from flannel to Calico
---

# About

This article describes how migrate an existing Kubernetes cluster with flannel networking to use Calico
networking. Calico provides a migration tool that performs a rolling update of the nodes in the cluster.
At the end, you will have a fully-functional Calico cluster using VXLAN networking between pods.

# Prerequisites

- A cluster with flannel for networking using the VXLAN backend.
- Flannel version v0.9.1 or greater (Canal version v3.7.0 or greater).
- Flannel must be configured to use the Kubernetes API for storing its configuration (as opposed to etcd).
- Flannel must be configured with `DirectRouting` disabled which is the default value.
- Flannel must have been installed using a Kubernetes daemon set.
- Cluster nodes must have rp_filter set to strict (1).  (Check with `sysctl net.ipv4.conf.all.rp_filter`)
- Cluster must allow for adding/deleting/modifying node labels.
- Cluster must allow for modification and removal of the flannel daemon set.
- For example, it must not be installed using the Kubernetes add-on manager.

# Procedure

1. First, install Calico.

   ```
   kubectl apply -f {{ "/manifests/flannel-migration/calico.yaml" | absolute_url }}
   ```

   Then, install the migration controller to initiate the migration.

   ```
   kubectl apply -f {{ "/manifests/flannel-migration/migration-job.yaml" | absolute_url }}
   ```

   Once applied, you will see nodes begin to update one at a time.

1. To monitor the migration, run the following command.

   ```
   kubectl get jobs -n kube-system flannel-migration
   ```

   The migration controller may be rescheduled several times during the migration when the node hosting
   it is upgraded. The installation is complete when the output of the above command shows 1/1 completions. For example:

   ```
   NAME                COMPLETIONS   DURATION   AGE
   flannel-migration   1/1           2m59s      5m9s
   ```

1. After completion, delete the migration controller with the following command.

   ```
   kubectl delete -f {{ "/manifests/flannel-migration/migration-job.yaml" | absolute_url }}
   ```
# Configuration options

The migration controller autodetects your flannel configuration, and in most cases, does not require
additional configuration. If you do require special configuration, the migration tool provides the following options,
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

# Troubleshooting

## Check migration status

The migration controller should run to completion. You can run the following command to view the controller's current status.

```
kubectl get pods -n kube-system -l k8s-app=flannel-migration-controller
```

## View migration logs

View migration logs using the following command.

```
kubectl logs -n kube-system -l k8s-app=flannel-migration-controller
```

The logs indicate if you need to take any actions.

# Rollback

Migration from Calico to flannel is not supported. If you experience a problem during the migration, follow these steps.


1. Remove the migration controller and Calico.

   ```
   kubectl delete -f {{ "/manifests/flannel-migration/migration-job.yaml" | absolute_url }}
   kubectl delete -f {{ "/manifests/flannel-migration/calico.yaml" | absolute_url }}
   ```

1. Determine the nodes which have been migrated to Calico.

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

Once the above steps have been completed on each node, perform the following steps.

1. Remove the `nodeSelector` from the flannel daemonset.

   ```
   kubectl patch ds/kube-flannel-ds-amd64 -n kube-system -p '{"spec": {"template": {"spec": {"nodeSelector": null}}}}'
   ```

1. Remove the migration label from all nodes.

   ```
   kubectl label node --all projectcalico.org/node-network-during-migration-
   ```
