---
title: Considerations between Kubernetes 1.5 and 1.6
---

There are several critical differences between Kubernetes versions 1.5 and 1.6,
some are due to API changes and some due to the tools used to deploy Kubernetes.
This document attempts to outline those differences and provide guidance to
convert manifests and configuration for the operation of Calico.

## Kubernetes RBAC

RBAC has been a feature available in Kubernetes 1.5 but in 1.6 it
is becoming more common to be enabled by default.  When RBAC is enabled, it is
necessary to configure RBAC roles and bindings and have the proper
credentials/certificates provided to the Calico components.  If the components
are created through Kubernetes manifests then adding the proper
`serviceAccountName` ensures the credentials are setup correctly but if the
components are ran standalone then it is up to the implementer to ensure the
proper credentials are provided.

#### Kubernetes RBAC when using an etcd Datastore

When Kubernetes RBAC is enabled and etcd is used as the datastore the
`calico/kube-policy-controller` and `calico/node` (for CNI installation) must
have RBAC configued as specified [here](rbac.yaml).

#### Kubernetes RBAC when using the Kubernetes Datastore Driver

When Kubernetes RBAC is enabled and the Kubernetes Datastore Driver is used then the
`calico/node` must have RBAC configured as specified [here](hosted/rbac.yaml).

## Ensuring components are scheduled

When Calico components are ran as pods by Kubernetes they need configuration
that ensures they can be scheduled at all times and will not be evicted even
when resources are scarce.
To ensure pods are schedulable at all times there are annotations and
tolerations that the Kuberenetes Scheduler looks for and they have changed
between Kubernetes 1.5 and 1.6.

#### Needed annotations with Kubernetes 1.5

```
annotations:
  scheduler.alpha.kubernetes.io/critical-pod: ''
  scheduler.alpha.kubernetes.io/tolerations: |
    [{"key": "dedicated", "value": "master", "effect": "NoSchedule" },
     {"key":"CriticalAddonsOnly", "operator":"Exists"}]
```

#### Needed annotations and tolerations with Kubernetes 1.6

```
annotations:
  scheduler.alpha.kubernetes.io/critical-pod: ''
tolerations:
  - key: node-role.kubernetes.io/master
    effect: NoSchedule
  - key: CriticalAddonsOnly
    operator: Exists
```

## Kubeadm changes

Kubeadm has seen some changes with the release of 1.6 too.  The differences
listed here should only be of concern when deploying or working with a cluster
deployed with the kubeadm tool.

Master node label (used in nodeSelector to run pods on master):

* For kubeadm pre-1.5 `kubeadm.alpha.kubernetes.io/role: master`
* For kubeadm 1.6+ `node-role.kubernetes.io/master: ""`

Flag for specifying the CIDR used in the cluster:

* For kubeadm pre-1.5: `--cluster-cidr`
* For kubeadm 1.6+  `--pod-network-cidr`
