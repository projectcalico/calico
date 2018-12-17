---
title: Installing Calico for policy (advanced)
canonical_url: 'https://docs.projectcalico.org/v3.4/getting-started/kubernetes/installation/other'
---

You can also use {{site.prodname}} just for policy enforcement and achieve networking 
with another solution, such as static routes or a Kubernetes cloud provider integration. 

To install {{site.prodname}} in this mode using the Kubernetes API datastore,
complete the following steps.

1. Ensure that you have a Kubernetes cluster that meets the 
   {{site.prodname}} [system requirements](../requirements). If you don't, 
   follow the steps in [Using kubeadm to create a cluster](http://kubernetes.io/docs/getting-started-guides/kubeadm/).

1. If your cluster has RBAC enabled, issue the following command to 
   configure the roles and bindings that {{site.prodname}} requires.

   ```
   kubectl apply -f \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/rbac-kdd.yaml
   ```
   > **Note**: You can also 
   > [view the manifest in your browser](hosted/rbac-kdd.yaml){:target="_blank"}.
   {: .alert .alert-info}

1. Ensure that the Kubernetes controller manager has the following flags
   set: <br>
   `--cluster-cidr=192.168.0.0/16` and `--allocate-node-cidrs=true`. 

   > **Tip**: On kubeadm, you can pass `--pod-network-cidr=192.168.0.0/16` 
   > to kubeadm to set both Kubernetes controller flags.
   {: .alert .alert-success}

1. Download the {{site.prodname}} policy-only manifest for the Kubernetes API datastore.
   
   ```bash
   curl \
   {{site.url}}/{{page.version}}/getting-started/kubernetes/installation/hosted/kubernetes-datastore/policy-only/1.7/calico.yaml \
   -O
   ```
   
1. If your cluster contains more than 50 nodes:

   - In the `ConfigMap` named `calico-config`, locate the `typha_service_name`,
     delete the `none` value, and replace it with `calico-typha`.

   - Modify the replica count in the`Deployment` named `calico-typha`
     to the desired number of replicas.
    
     ```
     apiVersion: apps/v1beta1
     kind: Deployment
     metadata:
       name: calico-typha
       ...
     spec:
       ...
       replicas: <number of replicas>
     ```
   
     We recommend at least one replica for every 200 nodes and no more than 
     20 replicas. In production, we recommend a minimum of three replicas to reduce 
     the impact of rolling upgrades and failures.

     > **Tip**: If you set `typha_service_name` without increasing the replica 
     > count from its default of `0` Felix will try to connect to Typha, find no 
     > Typha instances to connect to, and fail to start.
     {: .alert .alert-success}

1. Apply the manifest using the following command.

   ```bash
   kubectl apply -f calico.yaml
   ```
