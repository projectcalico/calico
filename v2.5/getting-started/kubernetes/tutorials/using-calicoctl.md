---
title: Using calicoctl in Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.1/getting-started/kubernetes/tutorials/using-calicoctl'
---

There are two ways to run `calicoctl` in Kubernetes:

- As a standalone binary
- As a Kubernetes pod

### a. Running calicoctl as a standalone binary

You can install calicoctl by [downloading the appropriate release]({{site.baseurl}}/{{page.version}}/releases) to any
machine with access to your etcd cluster by setting `ETCD_ENDPOINTS`. For example:

```
ETCD_ENDPOINTS=http://etcd:2379 calicoctl get profile
```

>**Note for kubeadm deployments**
>
> Calico is not configured to use the etcd run by kubeadm on the Kubernetes master.
> Instead, it launches its own instance of etcd as a pod, available at
`http://10.96.232.136:6666`.
>Ensure you are connecting to the correct etcd or you will not see any of the expected data.

### b. Running calicoctl as a Kubernetes Pod

The `calico/ctl` docker image can be deployed as a pod and used to run calicoctl
commands. This pod will need to be configured for the Kubernetes environment it is in.

>**Note**
>
>When calicoctl is run as a Pod, the `calicoctl node ...` suite of commands is not available.


For the **etcd backend** (e.g. kubeadm):

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/calicoctl.yaml
```

For **Kubernetes Datastore Backend**:

```
kubectl apply -f {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/calicoctl.yaml
```

You can then run `calicoctl` commands through the Pod using `kubectl`:

```
$ kubectl exec -ti -n kube-system calicoctl -- /calicoctl get profiles -o wide
NAME                 TAGS
k8s_ns.default       k8s_ns.default
k8s_ns.kube-system   k8s_ns.kube-system
```

See the [calicoctl reference guide]({{site.baseurl}}/{{page.version}}/reference/calicoctl) for more information.
