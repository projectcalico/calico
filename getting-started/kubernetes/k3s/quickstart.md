---
title: Quickstart for Calico on K3s
description: Install Calico on a single-host K3s cluster for testing or development in under 5 minutes.
canonical_url: '/getting-started/kubernetes/k3s/quickstart'
---

### Overview

This quickstart gets you a single-host K3s cluster with {{site.prodname}}
in approximately 5 minutes. You can use this cluster for testing and
development.

### Requirements

- x86-64 processor
- 1CPU
- 1GB Ram
- 10GB free disk space
- Ubuntu 16.04 (amd64), Ubuntu 18.04 (amd64)
   > **Note**: K3s supports ARM proccessors too, this tutorial was tested against x86-64 processor environment.
   > For more detail please visit {% include open-new-window.html text='this link' url='https://rancher.com/docs/k3s/latest/en/installation/installation-requirements/#operating-systems' %}.
   {: .alert .alert-info}

### Before you begin

- We assume you have a running instance of Linux (meeting the requirement) with root or sudo privileges up and running.
- In this tutorial we will guide you to implement a minimal K3s cluster with {{ site.prodname}}.


### Create a single-host K3s cluster

1. Initialize the master using the following command.

    ```
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --cluster-cidr=192.168.0.0/16 --disable=traefik" sh -
    ```

   > **Note**: If 192.168.0.0/16 is already in use within your network you must select a different pod network
   > CIDR by replacing 192.168.0.0/16 in the above command. 
   {: .alert .alert-danger}



2. Install {{site.prodname}} with the following command.

   ```
   kubectl apply -f {{ "/manifests/calico.yaml" | absolute_url }}
   ```

   > **Note**: You can also
   > [view the YAML in a new tab]({{ "/manifests/calico.yaml" | absolute_url }}){:target="_blank"}.
   {: .alert .alert-info}

   You should see the following output.

   ```
    configmap/calico-config created
    customresourcedefinition.apiextensions.k8s.io/bgpconfigurations.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/bgppeers.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/blockaffinities.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/clusterinformations.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/felixconfigurations.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/globalnetworkpolicies.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/globalnetworksets.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/hostendpoints.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/ipamblocks.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/ipamconfigs.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/ipamhandles.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/ippools.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/kubecontrollersconfigurations.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/networkpolicies.crd.projectcalico.org created
    customresourcedefinition.apiextensions.k8s.io/networksets.crd.projectcalico.org created
    clusterrole.rbac.authorization.k8s.io/calico-kube-controllers created
    clusterrolebinding.rbac.authorization.k8s.io/calico-kube-controllers created
    clusterrole.rbac.authorization.k8s.io/calico-node created
    clusterrolebinding.rbac.authorization.k8s.io/calico-node created
    daemonset.apps/calico-node created
    serviceaccount/calico-node created
    deployment.apps/calico-kube-controllers created
    serviceaccount/calico-kube-controllers created
   ```
   {: .no-select-button}

3. Confirm that all of the pods are running with the following command.


   ```
   watch kubectl get pods --all-namespaces
   ```

   Wait until each pod shows the `STATUS` of `Running`.

   ```
   NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE
   kube-system   {{site.noderunning}}-9hn9z                          1/1     Running   0          23m
   kube-system   local-path-provisioner-6d59f47c7-drznc     1/1     Running   0          38m
   kube-system   calico-kube-controllers-789f6df884-928lt   1/1     Running   0          23m
   kube-system   metrics-server-7566d596c8-qxlfz            1/1     Running   0          38m
   kube-system   coredns-8655855d6-blzl5                    1/1     Running   0          38m
   ```
   {: .no-select-button}

4. Press CTRL+C to exit `watch`.


5. Confirm that you now have a node in your cluster with the
   following command.

   ```
   kubectl get nodes -o wide
   ```

   It should return something like the following.

   ```
   NAME         STATUS   ROLES    AGE   VERSION        INTERNAL-IP    EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION       CONTAINER-RUNTIME
   k3s-master   Ready    master   40m   v1.18.2+k3s1   172.16.2.128   <none>        Ubuntu 18.04.3 LTS   4.15.0-101-generic   containerd://1.3.3-k3s2
   ```
   {: .no-select-button}

Congratulations! You now have a single-node K3s cluster
equipped with {{site.prodname}}.

### Next steps
- [Create a user interface that shows blocked and allowed connections in real time]({{ site.baseurl }}/security/tutorials/kubernetes-policy-demo/kubernetes-demo)
