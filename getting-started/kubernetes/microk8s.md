---
title: Quickstart for Calico on MicroK8s
description: Install Calico on a single-host MicroK8s cluster for testing or development in under 5 minutes.
canonical_url: '/getting-started/kubernetes/microk8s'
---

### Big picture

This quickstart gets you a single-host MicroK8s cluster with {{site.prodname}} in approximately 5 minutes.

### Value

MicroK8s is a small, fast implementation of Kubernetes.

Use this quickstart to quickly and easily try {{site.prodname}} features with MicroK8s.

### Before you begin

- Make sure you have a linux host that meets the following requirements:
  - 4GB RAM
  - 20GB free disk space
  - Ubuntu 20.04 LTS, 18.04 LTS or 16.04 LTS (or an operating system with the support of `snapd`)

### How to


1. Initialize the master using the following command.
   
   > **Note**: MicroK8s uses {% include open-new-window.html text='snap' url='https://snapcraft.io/docs/snapcraft-overview' %} bundle to publish its releases, since snap enviroment uses different folder paths
   > it is not possible to install {{site.prodname}} using manifest or operator.
   >
   > If you like to learn more about MicroK8s paths {% include open-new-window.html text='click here.' url='https://github.com/ubuntu/microk8s/blob/master/docs/build.md#assembling-the-calico-cni-manifest' %}
   {: .alert .alert-info }

   ```
   snap install microk8s --classic --channel=edge/ha-preview
   ```

1. Enable dns services.
   
   > **Note**: DNS service is not required. However, it is recommended to enable this feature.
   {: .alert .alert-info}

   ```
   microk8s enable dns
   ```

1. Check your cluster status
   
   ```
   microk8s kubectl get pods -A
   ```

   You should see a result similar to

   ```
   NAMESPACE     NAME                                       READY   STATUS    RESTARTS   AGE
   kube-system   calico-node-drmr8                          1/1     Running   0          62s
   kube-system   calico-kube-controllers-555fc8cc5c-dbx8j   1/1     Running   0          62s
   ```

### Next steps

**Required**
- [Install and configure calicoctl](../clis/calicoctl/install)

**Recommended tutorials**
- [Secure a simple application using the Kubernetes NetworkPolicy API](../../security/tutorials/kubernetes-policy-basic)
- [Control ingress and egress traffic using the Kubernetes NetworkPolicy API](../../security/tutorials/kubernetes-policy-advanced)
- [Run a tutorial that shows blocked and allowed connections in real time](../../security/tutorials/kubernetes-policy-demo/kubernetes-demo)
