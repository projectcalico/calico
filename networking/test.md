---
title: Manage IP pools
description: Move pods to a different IP pool, or change IP pool block size to efficiently use IP addresses.
---

### Big picture

Move pods to a different IP pool, or change IP pool block size without network disruption.

### Value

Pods are assigned IP addresses from IP pools that you configure in {{site.prodname}}. As pods increase, you may need to increase the number of IP addresses available for pods to use. Or, you may need to move pods from a CIDR that was used by mistake, or expand/shrink an IP pool block size as nodes increase. For all of these scenarios, {{site.prodname}} provides a way to change IP pools without disruption to the cluster. 

### Features

This how-to guide uses the following {{site.prodname}} features:

- **IPPool** resource 

### Concepts

#### Best practice: create IP pools within the same cluster CIDR

Kubernetes expects that all pods have IP addresses within the same cluster CIDR. Although {{site.prodname}} technically supports using multiple disjoint IP pool CIDRs, we do not recommend it; pods allocated addresses outside of the Kubernetes cluster CIDR will lose network connectivity.   

### Before you begin...

**Required**

- Verify that you are using {{site.prodname}} IPAM
  
  This guide is only relevant if you are using Calico IPAM.

  1. ssh to one of your Kubernetes nodes and view the CNI configuration.  

    ```bash
      cat /etc/cni/net.d/10-calico.conflist
  ```

  1. Look for the "type" entry:

    <pre>
       "ipam": {
             "type": "calico-ipam"
        }, 
    </pre>

    If the type is “calico-ipam”, you are good to go. If the IPAM is set to something else, or the 10-calico.conflist file does not exist, you cannot use this feature in your cluster. 

- Verify orchestrator support for changing the pod network CIDR

  Although Kubernetes supports changing the pod network CIDR, not all orchestrators do. For example, **OpenShift** does not support this feature as described in [`osm_cluster_network_cidr configuration`](https://docs.openshift.org/latest/install_config/install/advanced_install.html#configuring-cluster-variables). Check your orchestrator documentation to verify. 

**Recommended**

  Understand the basics of [Calico IPAM]({{site.baseurl}}/get-started-ip-addresses)

### How to

> **Important!** The steps in this section are ordered to ensure that existing pod connectivity is not affected. If you do not follow this order, (and delete the old IP pool before you create and verify the new pool), existing pods will be affected. Also, when pods are deleted, applications may be temporarily unavailable (depending on the type of application); plan accordingly. 
{: .alert .alert-danger }

- [Migrate pods from one IP pool to another](#migrate-pods-from-one-ip-pool-to-another)
- [Expand or shrink IP pool block sizes](#expand-or-shrink-ip-pool-block-sizes)

#### Migrate workloads from one IP pool to another

Whether you want to migrate pods from one IP pool to a pool with a larger CIDR, or because pods were created in the wrong IP pool in error, follow these steps:

1. Add a new IP pool.  
   **Note**: The new IP pool must be within the same cluster CIDR.
1. Disable the old IP pool.  
   **Note**: Disabling an IP pool only prevents new IP address allocations; it does not affect the networking of existing pods.
1. Delete pods from the old IP pool.  
   This includes any new pods that may have been created with the old IP pool prior to disabling the pool.
1. Verify that new pods get an address from the new IP pool.
1. Delete the old IP pool.

[See step-by-step tutorial](#example-migrate-from-one-ip-pool-to-another)

#### Expand or shrink IP pool block size

By default, the {{site.prodname}} IPAM block size for an IP pool is /26. You can expand the `blockSize` using a lower number (for example /8). Or, you can shrink a `blockSize` using a larger number (for example, /28). Changing the `blockSize` requires an extra step (creating a temporary IP pool), because you cannot change the `blockSize` after it is initially created.

The high-level steps to follow are:

1. Add a new temporary IP pool. 
   **Note**: The new IP pool must not be within the same cluster CIDR.
1. Disable the old IP pool.
   **Note**: Disabling an IP pool only prevents new IP address allocations; it does not affect the networking of existing pods.
1. Delete pods from the old IP pool.
   This includes any new pods that may have been created with the old IP pool prior to disabling the pool.
1. Verify that new pods get an address from the new IP pool.
1. Delete the old IP pool.
1. Create a new pool with custom CIDR block within the same cluster CIDR
1. Disable temporary IP pool.
1. Delete pods from the temporary IP pool.
1. Delete temporary IP pool

[Follow step-by-step tutorial](#example-expand-or-shrink-ip-pool-block-size)

#### Tutorial

- [Example: Migrate from one IP pool to another](#example-migrate-from-one-ip-pool-to-another)
- [Example: Expand or shrink IP pool block size](#example-expand-or-shrink-ip-pool-block-size)

**Example: Migrate from one IP pool to another one**

In the following example, we created a Kubernetes cluster using **kubeadm**. But we accidentially assigned the CIDR for pods to be: **192.168.0.0/16**. The CIDR should be: **10.0.0.0/16** (within the cluster CIDR). 

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

```bash
calicoctl get ippool -o wide

```
<pre>
NAME                  CIDR             NAT    IPIPMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     false
new-pool              10.0.0.0/16      true   Always     false
</pre>

#### Step 2: Disable the old IP pool

List the existing IP pool definition.

```bash
calicoctl get ippool -o yaml > pool.yaml

```

```
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
```

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

```bash
calicoctl apply -f pool.yaml

```

Verify the changes.

```bash
calicoctl get ippool -o wide

```

<pre>
NAME                  CIDR             NAT    IPIPMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     true
new-pool              10.0.0.0/16      true   Always     false
</pre>

#### Step 3: Delete pods from the old IP pool

Next, we delete all of the existing pods from the old IP pool. (In our example, **coredns** is our only pod; for multiple pods you would trigger a deletion for all pods in the cluster.)

```bash
kubectl delete pod -n kube-system coredns-6f4fd4bdf-8q7zp

```

#### Step 4: Verify that new pods get an address from the new IP pool

1. Create a test namespace and nginx pod. 
 
   ```bash
   kubectl create ns ippool-test

   ```

1. Create an nginx pod. 
  
   ```bash
   kubectl -n ippool-test create deployment nginx --image nginx

   ```

1. Verify that the new pod gets an IP address from the new range.
    
   ```bash
   kubectl -n ippool-test get pods -l app=nginx -o wide

   ```

1. Clean up the ippool-test namespace.  
 
   ```bash
   kubectl delete ns ippool-test

   ```

#### Step 5: Delete the old IP pool

Now that you've verified that pods are getting IPs from the new range, you can safely delete the old pool.

```bash
calicoctl delete pool default-ipv4-ippool

```

**Example #2: Shrink a block size**

In the following example, we created a Kubernetes cluster with default CIDR block size of /26 but want to change it to /28.

#### Step 1: Add a new IP pool

We add a new IPPool with the CIDR range, 10.0.0.0/16.

Create a new-pool.yaml.

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

Apply the changes.

```
calicoctl apply -f new-pool.yaml
```

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
calicoctl get ippool -o yaml --export > pool.yaml
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

Edit pool.yaml, and disable this IP pool by setting: `disabled: true`

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

Remember, disabling a pool only affects new IP allocations; networking for existing pods is not affected.

Apply the changes.

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

### Step 3: Delete pods from the old IP pool

Next, we delete all of the existing pods from the old IP pool. (In our example, coredns is our only pod; for multiple pods you would trigger a deletion for all pods in the cluster.)

```
kubectl delete pod -n kube-system coredns-6f4fd4bdf-8q7zp
```
You can restart all pods with just one command. WARNING! This is disruptive and may take several minutes depending on the number of pods deployed.

```
kubectl delete pod -A --all
```

#### Step 4: Delete the old IP poo

Now that you’ve verified that pods are getting IPs from the new range, you can safely delete the old pool.

```
calicoctl delete pool default-ipv4-ippool
```

#### Step 5: Create a new pool with custom cidr block

<pre>
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: default-ipv4-ippool
spec:
  blockSize: 28
  cidr: 192.0.0.0/16
  ipipMode: Always
  natOutgoing: true
</pre>

Apply the changes.

```
calicoctl apply -f pool.yaml
```

#### Step 6: Disable temporary IP pool

```
calicoctl get ippool -o yaml --export > pool.yaml
```

<pre>
apiVersion: projectcalico.org/v3
items:
- apiVersion: projectcalico.org/v3
  kind: IPPool
  metadata:
    name: default-ipv4-ippool
  spec:
    blockSize: 28
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
    
Edit pool.yaml, and disable this IP pool by setting: `disabled: true`

<pre>
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: new-pool
spec:
  cidr: 10.0.0.0/16
  ipipMode: Always
  natOutgoing: true
  disabled: true
</pre>

Apply the changes.

```
calicoctl apply -f pool.yaml
```

#### Step 7: Delete pods from the temporary IP pool.

Next, we delete all of the existing pods from the old IP pool. (In our example, coredns is our only pod; for multiple pods you would trigger a deletion for all pods in the cluster.)

```
kubectl delete pod -n kube-system coredns-6f4fd4bdf-8q7zp
```
You can restart all pods with just one command. WARNING! This is disturbtive and may take several minutes depending on the number of pods deployed.

```
kubectl delete pod -A --all
```
You can validate your pods and block size are correct by running the following commands

```
kubectl get pods --all-namespaces -o wide
calicoctl ipam show --show-blocks
```
#### Step 8: Delete the temporary IP pool.

Clean up the IP pools by deleting the temporary IP pool

```
calicoctl delete pool new-pool
```

### Above and beyond

- [IP pools reference]({{ site.baseurl }}/reference/resources/ippool)
