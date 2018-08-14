---
title: Quickstart for Calico on Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.2/getting-started/kubernetes/'
---


### Overview

This quickstart gets you a single-host Kubernetes cluster with Calico
in approximately 15 minutes. You can use this cluster for testing and
development.

To deploy a cluster suitable for production, refer to [Installation](https://docs.projectcalico.org/v2.6/getting-started/kubernetes/installation/).


### Requirements

- AMD64 processor
- 2CPU
- 2GB RAM
- 10GB free disk space
- RedHat Enterprise Linux 7.x+, CentOS 7.x+, Ubuntu 16.04+, or Debian 8.x+


### Before you begin

[Follow the Kubernetes instructions to install kubeadm](https://kubernetes.io/docs/setup/independent/install-kubeadm/){:target="_blank"}.

> **Note**: After installing kubeadm, do not power down or restart
the host. Instead, continue directly to the
[next section to create your cluster](#create-a-single-host-kubernetes-cluster).
{: .alert .alert-info}


### Create a single-host Kubernetes cluster

1. As a regular user with sudo privileges, open a terminal on the host that
   you installed kubeadm on.

1. Update your package definitions and upgrade your existing packages.

   ```
   sudo apt-get update && sudo apt-get upgrade
   ```

1. Initialize the master using the following command.

   ```
   sudo kubeadm init --pod-network-cidr=192.168.0.0/16
   ```

1. Execute the following commands to configure kubectl (also returned by
   `kubeadm init`).

   ```
   mkdir -p $HOME/.kube
   sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
   sudo chown $(id -u):$(id -g) $HOME/.kube/config
   ```

1. Install Calico and a single node etcd with the following command.

   ```
   kubectl apply -f \
   https://docs.projectcalico.org/v2.6/getting-started/kubernetes/installation/hosted/kubeadm/1.6/calico.yaml
   ```

   > **Note**: You can also
   > [view the YAML in your browser](https://docs.projectcalico.org/v2.6/getting-started/kubernetes/installation/hosted/kubeadm/1.6/calico.yaml){:target="_blank"}.
   {: .alert .alert-info}

   You should see the following output.

   ```
   configmap "calico-config" created
   daemonset "calico-etcd" created
   service "calico-etcd" created
   daemonset "calico-node" created
   deployment "calico-kube-controllers" created
   deployment "calico-policy-controller" created
   clusterrolebinding "calico-cni-plugin" created
   clusterrole "calico-cni-plugin" created
   serviceaccount "calico-cni-plugin" created
   clusterrolebinding "calico-kube-controllers" created
   clusterrole "calico-kube-controllers" created
   serviceaccount "calico-kube-controllers" created
   ```

1. Confirm that all of the pods are running with the following command.

   ```
   watch kubectl get pods --all-namespaces
   ```

   Wait until each pod has the `STATUS` of `Running`.

   ```
   NAMESPACE    NAME                                       READY  STATUS   RESTARTS  AGE
   kube-system  calico-etcd-x2482                          1/1    Running  0         2m
   kube-system  calico-kube-controllers-6ff88bf6d4-tgtzb   1/1    Running  0         2m
   kube-system  calico-node-24h85                          2/2    Running  0         2m
   kube-system  etcd-jbaker-virtualbox                     1/1    Running  0         6m
   kube-system  kube-apiserver-jbaker-virtualbox           1/1    Running  0         6m
   kube-system  kube-controller-manager-jbaker-virtualbox  1/1    Running  0         6m
   kube-system  kube-dns-545bc4bfd4-67qqp                  3/3    Running  0         5m
   kube-system  kube-proxy-8fzp2                           1/1    Running  0         5m
   kube-system  kube-scheduler-jbaker-virtualbox           1/1    Running  0         5m
   ```

1. Press CTRL+C to exit `watch`.

1. Remove the taints on the master so that you can schedule pods
   on it.

   ```
   kubectl taint nodes --all node-role.kubernetes.io/master-
   ```

   It should return the following.

   ```
   node "<your-hostname>" untainted
   ```

1. Switch to a root shell.

   ```
   sudo -i
   ```

1. Scroll upward in your terminal to locate the `join` command
   returned by `kubeadm init`. Copy the `join` command, paste it
   in your shell prompt, and add `--skip-preflight-checks` to the end.

   **Syntax**:
   ```
   kubeadm join --token <token> <master-ip>:<master-port> \
   --discovery-token-ca-cert-hash sha256:<hash> \
   --skip-preflight-checks
   ```

   **Example**:
   ```
   kubeadm join --token eea8bd.4d282767b6b962ca 10.0.2.15:6443 \
   --discovery-token-ca-cert-hash sha256:0e6e73d52066326023432f417a566afad72667e6111d2236b69956b658773255
   --skip-preflight-checks
   ```

1. Exit the root shell.

   ```
   exit
   ```

1. Confirm that you now have a node in your cluster with the
   following command.

   ```
   kubectl get nodes -o wide
   ```

   It should return something like the following.

   ```
   NAME             STATUS  ROLES   AGE  VERSION  EXTERNAL-IP  OS-IMAGE            KERNEL-VERSION     CONTAINER-RUNTIME
   <your-hostname>  Ready   master  1h   v1.8.x   <none>       Ubuntu 16.04.3 LTS  4.10.0-28-generic  docker://1.12.6
   ```

Congratulations! You now have a single-host Kubernetes cluster
equipped with Calico.


### Next steps

**[Secure a simple two-tier application using the Kubernetes `NetworkPolicy` API](tutorials/simple-policy)**

**[Control ingress and egress traffic using the Kubernetes `NetworkPolicy` API](tutorials/advanced-policy)**

**[Create a user interface that shows blocked and allowed connections in real time](tutorials/stars-policy/)**

**[Using the calicoctl CLI tool](https://docs.projectcalico.org/v2.6/getting-started/kubernetes/tutorials/using-calicoctl)**

**[Configure BGP to peer with your underlying infrastructure (private cloud only)](https://docs.projectcalico.org/v2.6/usage/configuration/bgp)**
