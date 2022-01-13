---
title: Quickstart for Calico on MicroK8s
description: Install Calico on a single-host MicroK8s cluster for testing or development in under 5 minutes.
canonical_url: '/getting-started/kubernetes/microk8s'
---

### Big picture

Install a single node MicroK8s cluster with {{site.prodname}} in approximately 5 minutes.

### Value

MicroK8s is a lightweight upstream Kubernetes distribution package to run as an immutable container.

Use this quickstart to quickly and easily try {{site.prodname}} features with MicroK8s.

### Before you begin

- Make sure you have a linux host that meets the following requirements:
  - 4GB RAM
  - 20GB free disk space
  - Ubuntu 20.04 LTS, 18.04 LTS or 16.04 LTS (or another operating system that supports `snapd`)

### How to

1. Initialize the node using the following command.
   
   ```
   snap install microk8s --classic
   ```

   > You can check out other versions of Kubernetes MicroK8s implementation published in snap using `snap info microk8s` command.
   {: .alert .alert-info }

1. Enable dns services.
 
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
   kube-system   calico-node-b82zp                          1/1     Running   0          64s
   kube-system   calico-kube-controllers-555fc8cc5c-b7cp6   1/1     Running   0          64s
   kube-system   coredns-588fd544bf-mbc7n                   1/1     Running   0          39s
   ```

The geeky details of what you get:
{% include geek-details.html details='Policy:Calico,IPAM:Calico,CNI:Calico,Overlay:VXLAN,Routing:Calico,Datastore:Kubernetes' %}

### Next steps

**Required**
- [Install and configure calicoctl]({{site.basurl}}/maintenance/clis/calicoctl/install)

**Optional**
- {% include open-new-window.html text='Add another node to form a multi-node cluster' url='https://microk8s.io/docs/clustering' %}

**Recommended tutorials**
- [Secure a simple application using the Kubernetes NetworkPolicy API]({{site.basurl}}/security/tutorials/kubernetes-policy-basic)
- [Control ingress and egress traffic using the Kubernetes NetworkPolicy API]({{site.basurl}}/security/tutorials/kubernetes-policy-advanced)
- [Run a tutorial that shows blocked and allowed connections in real time]({{site.basurl}}/security/tutorials/kubernetes-policy-demo/kubernetes-demo)
