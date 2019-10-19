---
title: Migrate from one IP pool to another
redirect_from: latest/networking/migrate-pools
---

### Big picture

Migrate pods from one IP pool to another on a running cluster without network disruption.

### Value

Pods are assigned IP addresses from IP pools that you configure in {{site.prodname}}. As the number of pods increase, you may need to increase the number of addresses available for pods to use. Or, you may need to move pods from a CIDR that was used by mistake. {{site.prodname}} lets you migrate from one IP pool to another one on a running cluster without network disruption. 

### Features

This how-to guide uses the following {{site.prodname}} features:

- **IPPool** resource 

### Concepts

#### IP pools and cluster CIDRs

{{site.prodname}} supports using multiple disjoint IP pool CIDRs within the cluster. However, Kubernetes expects that all pods have addresses within the same cluster CIDR. This means that although it is technically feasible to create an IP pool outside of the cluster CIDR, we do not recommend it. Pods allocated addresses outside of the Kubernetes cluster CIDR will lose network connectivity.

### Before you begin...

**Verify that you are using {{site.prodname}} IPAM**. 

To verify, ssh to one of your Kubernetes nodes and view the CNI configuration.  

```
cat /etc/cni/net.d/10-calico.conflist

```

Look for the "type" entry:

<pre>
   "ipam": {
         "type": "calico-ipam"
    }, 
</pre>

If the type is “calico-ipam”, you are good to go. If the IPAM is set to something else, or the 10-calico.conflist file does not exist, you cannot use this feature in your cluster. 

**Verify orchestrator support for changing the pod network CIDR**.

Although Kubernetes supports changing the pod network CIDR, not all orchestrators do. For example, OpenShift does not support this feature as described in [`osm_cluster_network_cidr configuration`](https://docs.openshift.org/latest/install_config/install/advanced_install.html#configuring-cluster-variables). Check your orchestrator documentation to verify. 

### How to

#### Migrate from one IP pool to another

Follow these steps to migrate pods from one IP pool to another pool. 

> **Important!** If you follow these steps, existing pod connectivity will not be affected. (If you delete the old IP pool before you create and verify the new pool, existing pods will be affected.) When pods are deleted, applications may be temporarily unavailable (depending on the type of application); plan accordingly. 
{: .alert .alert-danger }

1. Add a new IP pool.  
   **Note**: The new IP pool must be within the same cluster CIDR.
1. Disable the old IP pool.  
   **Note**: Disabling an IP pool only prevents new IP address allocations; it does not affect the networking of existing pods.
1. Delete pods from the old IP pool.  
   This includes any new pods that may have been created with the old IP pool prior to disabling the pool.
1. Verify that new pods get an address from the new IP pool.
1. Delete the old IP pool.

### Tutorial

In the following example, we created a Kubernetes cluster using **kubeadm**. But we accidentially assigned the CIDR for pods to be: **192.168.0.0/16**. We now want to change the CIDR to: **10.0.0.0/16** (within the cluster CIDR). 

Let’s run `calicoctl get ippool -o wide` to see the IP pool, **default-ipv4-ippool**.

<pre>
NAME                  CIDR             NAT    IPIPMODE   VXLANMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     Never       false
</pre>

When we run `calicoctl get wep --all-namespaces`, we see that a pod is created using the default range (192.168.52.130/32).

<pre>
NAMESPACE     WORKLOAD                   NODE      NETWORKS            INTERFACE
kube-system   coredns-6f4fd4bdf-8q7zp   vagrant   192.168.52.130/32   cali800a63073ed
</pre>

Let’s get started changing this pod to the new IP pool (10.0.0.0/16).

#### Step 1: Add a new IP pool

We add a new **IPPool** with the CIDR range, **10.0.0.0/16**.

<pre>
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: new-pool
spec:
  cidr: 10.0.0.0/16
  ipipMode: Always
  natOutgoing: true
</pre>

Let’s verify the new IP pool.

```
calicoctl get ippool -o wide

```
<pre>
NAME                  CIDR             NAT    IPIPMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     false
new-pool              10.0.0.0/16      true   Always     false
</pre>

#### Step 2: Disable the old IP pool

List the existing IP pool definition.

```
calicoctl get ippool -o yaml > pool.yaml

```

<pre>
apiVersion: projectcalico.org/v3
items:
- apiVersion: projectcalico.org/v3
  kind: IPPool
  metadata:
    name: default-ipv4-ippool
  spec:
    cidr: 192.0.0.0/16
    ipipMode: Always
    natOutgoing: true
- apiVersion: projectcalico.org/v3
  kind: IPPool
  metadata:
    name: new-pool
  spec:
    cidr: 10.0.0.0/16
    ipipMode: Always
    natOutgoing: true
</pre>

Edit pool.yaml.

Disable this IP pool by setting: `disabled: true`

<pre>
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: default-ipv4-ippool
spec:
  cidr: 192.0.0.0/16
  ipipMode: Always
  natOutgoing: true
  disabled: true
</pre>

Apply the changes. 

Remember, disabling a pool only affects new IP allocations; networking for existing pods is not affected.

```
calicoctl apply -f pool.yaml

```

Verify the changes.

```
calicoctl get ippool -o wide

```

<pre>
NAME                  CIDR             NAT    IPIPMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     true
new-pool              10.0.0.0/16      true   Always     false
</pre>

#### Step 3: Delete pods from the old IP pool

Next, we delete all of the existing pods from the old IP pool. (In our example, **coredns** is our only pod; for multiple pods you would trigger a deletion for all pods in the cluster.)

```
kubectl delete pod -n kube-system coredns-6f4fd4bdf-8q7zp

```

#### Step 4: Verify that new pods get an address from the new IP pool

1. Create a test namespace and nginx pod. 
 
   ```
   kubectl create ns ippool-test

   ```

1. Create an nginx pod. 
  
   ```
   kubectl -n ippool-test create deployment nginx --image nginx

   ```

1. Verify that the new pod gets an IP address from the new range.
    
   ```
   kubectl -n ippool-test get pods -l app=nginx -o wide

   ```

1. Clean up the ippool-test namespace.  
 
   ```
   kubectl delete ns ippool-test

   ```

#### Step 5: Delete the old IP pool

Now that you've verified that pods are getting IPs from the new range, you can safely delete the old pool.

```
calicoctl delete pool default-ipv4-ippool

```

### Above and beyond

- [IP pools reference]({{ site.baseurl }}/{{ page.version }}/reference/resources/ippool)
