---
title: Quickstart for Calico on Kubernetes
description: Install a single-host Kubernetes cluster with Calico
canonical_url: '/getting-started/kubernetes/index'
---


### Overview

This quickstart gets you a single-host Kubernetes cluster with {{site.prodname}}
in approximately 15 minutes. You can use this cluster for testing and
development.

To deploy a cluster suitable for production, refer to [Installation](installation).


### Requirements

- AMD64 processor
- 2CPU
- 2GB RAM
- 10GB free disk space
- RedHat Enterprise Linux 7.x+, CentOS 7.x+, Ubuntu 16.04+, or Debian 9.x+


### Before you begin

- Ensure that {{site.prodname}} can manage `cali` and `tunl` interfaces on the host.
  If NetworkManager is present on the host, refer to
  [Configure NetworkManager](../../maintenance/troubleshooting#configure-networkmanager).

- [Follow the Kubernetes instructions to install kubeadm](https://kubernetes.io/docs/setup/independent/install-kubeadm/){:target="_blank"}.

   > **Note**: After installing kubeadm, do not power down or restart
   the host. Instead, continue directly to the
   [next section to create your cluster](#create-a-single-host-kubernetes-cluster).
   {: .alert .alert-info}


### Create a single-host Kubernetes cluster

1. As a regular user with sudo privileges, open a terminal on the host that
   you installed kubeadm on.

1. Initialize the master using the following command.

   ```
   sudo kubeadm init --pod-network-cidr=192.168.0.0/16
   ```

   > **Note**: If 192.168.0.0/16 is already in use within your network you must select a different pod network
   > CIDR, replacing 192.168.0.0/16 in the above command as well as in any manifests applied below.
   {: .alert .alert-info}

1. Execute the following commands to configure kubectl (also returned by
   `kubeadm init`).

   ```
   mkdir -p $HOME/.kube
   sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
   sudo chown $(id -u):$(id -g) $HOME/.kube/config
   ```

1. Install {{site.prodname}} with the following command.

   ```
   kubectl apply -f {{ "/manifests/calico.yaml" | absolute_url }}
   ```

   > **Note**: You can also
   > [view the YAML in a new tab]({{ "/manifests/calico.yaml" | absolute_url }}){:target="_blank"}.
   {: .alert .alert-info}

   You should see the following output.

   ```
   configmap "calico-config" created
   customresourcedefinition.apiextensions.k8s.io "felixconfigurations.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "ipamblocks.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "blockaffinities.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "ipamhandles.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "bgppeers.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "bgpconfigurations.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "ippools.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "hostendpoints.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "clusterinformations.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "globalnetworkpolicies.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "globalnetworksets.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "networksets.crd.projectcalico.org" created
   customresourcedefinition.apiextensions.k8s.io "networkpolicies.crd.projectcalico.org" created
   clusterrole.rbac.authorization.k8s.io "calico-kube-controllers" created
   clusterrolebinding.rbac.authorization.k8s.io "calico-kube-controllers" created
   clusterrole.rbac.authorization.k8s.io "calico-node" created
   clusterrolebinding.rbac.authorization.k8s.io "calico-node" created
   daemonset.extensions "calico-node" created
   serviceaccount "calico-node" created
   deployment.extensions "calico-kube-controllers" created
   serviceaccount "calico-kube-controllers" created
   ```
   {: .no-select-button}

1. Confirm that all of the pods are running with the following command.

   ```
   watch kubectl get pods --all-namespaces
   ```

   Wait until each pod has the `STATUS` of `Running`.

   ```
   NAMESPACE    NAME                                       READY  STATUS   RESTARTS  AGE
   kube-system  calico-kube-controllers-6ff88bf6d4-tgtzb   1/1    Running  0         2m45s
   kube-system  {{site.noderunning}}-24h85                          1/1    Running  0         2m43s
   kube-system  coredns-846jhw23g9-9af73                   1/1    Running  0         4m5s
   kube-system  coredns-846jhw23g9-hmswk                   1/1    Running  0         4m5s
   kube-system  etcd-jbaker-1                              1/1    Running  0         6m22s
   kube-system  kube-apiserver-jbaker-1                    1/1    Running  0         6m12s
   kube-system  kube-controller-manager-jbaker-1           1/1    Running  0         6m16s
   kube-system  kube-proxy-8fzp2                           1/1    Running  0         5m16s
   kube-system  kube-scheduler-jbaker-1                    1/1    Running  0         5m41s
   ```
   {: .no-select-button}

1. Press CTRL+C to exit `watch`.

1. Remove the taints on the master so that you can schedule pods
   on it.

   ```
   kubectl taint nodes --all node-role.kubernetes.io/master-
   ```

   It should return the following.

   ```
   node/<your-hostname> untainted
   ```
   {: .no-select-button}

1. Confirm that you now have a node in your cluster with the
   following command.

   ```
   kubectl get nodes -o wide
   ```

   It should return something like the following.

   ```
   NAME              STATUS   ROLES    AGE   VERSION   INTERNAL-IP   EXTERNAL-IP   OS-IMAGE             KERNEL-VERSION    CONTAINER-RUNTIME
   <your-hostname>   Ready    master   52m   v1.12.2   10.128.0.28   <none>        Ubuntu 18.04.1 LTS   4.15.0-1023-gcp   docker://18.6.1
   ```
   {: .no-select-button}

Congratulations! You now have a single-host Kubernetes cluster
equipped with {{site.prodname}}.


### Next steps

**[Secure a simple application using the Kubernetes `NetworkPolicy` API](../../security/tutorials/kubernetes-policy-basic)**

**[Control ingress and egress traffic using the Kubernetes `NetworkPolicy` API](../../security/tutorials/kubernetes-policy-advanced)**

**[Create a user interface that shows blocked and allowed connections in real time](../../security/tutorials/kubernetes-policy-demo/kubernetes-demo)**

**[Install and configure calicoctl](../calicoctl/install)**
