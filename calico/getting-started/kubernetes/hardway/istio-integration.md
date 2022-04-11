---
title: Istio integration
description: Enforce Calico network policy for Istio service mesh applications.
canonical_url: '/getting-started/kubernetes/hardway/istio-integration'
---

{{site.prodname}} policy integrates with {% include open-new-window.html text='Istio' url='https://istio.io' %} to allow you to write policies that enforce against
application layer attributes like HTTP methods or paths as well as against cryptographically secure identities. In this
lab we will enable this integration and test it out.

## Install CSI driver

{{site.prodname}} uses a Container Storage Interface (CSI) driver to enable secure connectivity between Felix and the Dikastes container
running in each pod.  It mounts a shared volume into which Felix inserts a Unix Domain Socket.

Execute the following command to install the CSI driver.

```bash
kubectl apply -f {{ site.baseurl }}/manifests/csi-driver.yaml
```

Verify the `csi-node-driver` pods are running.

```bash
kubectl get pods -n kube-system
```

You should see something similar to the following:

```
csi-node-driver-gk9mq                              2/2     Running   0             2m9s
csi-node-driver-jhngv                              2/2     Running   0             2m9s
csi-node-driver-kcqnj                              2/2     Running   0             2m9s
csi-node-driver-n78lx                              2/2     Running   0             2m9s
csi-node-driver-nrbvd                              2/2     Running   0             2m9s
```
{: .no-select-button}

## Install Istio

[Follow the instructions here]({{site.baseurl}}/security/app-layer-policy) to enable application layer policy, install Istio, update the
Istio sidecar injector and add Calico authorization services to the Istio mesh.

## Add Istio namespace label to the default namespace

Application layer policy is only enforced on pods that are started with the
Envoy and Dikastes sidecars.  Pods that do not have these sidecars will
only enforce standard {{site.prodname}} network policy.

You can control this on a per-namespace basis.  To enable Istio and application
layer policy in a namespace, add the label `istio-injection=enabled`.

Label the default namespace, which you will use for the tutorial.

```bash
kubectl label namespace default istio-injection=enabled
```


## Test application layer policy

You can test application layer policy by following the [Application Layer Policy tutorial](/security/tutorials/app-layer-policy/enforce-policy-istio).

