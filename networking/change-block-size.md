---
title: Change IP pool block size
description: Expand or shrink the IP pool block size to efficiently manage IP pool addresses. 
---

### Big picture

Expand or shrink the IP pool block size to efficiently manage IP pool addresses. 

### Value

{{site.prodname}} provides a safe way to change the IP pool block size without disrupting clusters. 

### Features

This how-to guide uses the following {{site.prodname}} features:

- **IPPool** resource with `blockSize` field

### Concepts

#### Best practices

- **Create IP pools within the same cluster CIDR** 

   Kubernetes expects that all pods have IP addresses within the same cluster CIDR. Although {{site.prodname}} technically supports using multiple disjoint IP pool CIDRs, we do not recommend it; pods allocated addresses outside of the Kubernetes cluster CIDR will lose network connectivity. 
  
- **Determine IP pool block size before installing {{site.prodname}}** 

   Because the `blockSize` field cannot be edited directly after installation, you must use a three-step process to make the changes and avoid disruption to clusters. However, this article provides the steps should you need to change `blockSize` after installation.

### Before you begin...

**Required**

- Verify that you are using {{site.prodname}} IPAM. This guide is only relevant if you are using Calico IPAM.

  ssh to one of your Kubernetes nodes and view the CNI configuration.  

    ```bash
      cat /etc/cni/net.d/10-calico.conflist
     ```
  Look for the "type" entry:
    <pre>
       "ipam": {
             "type": "calico-ipam"
        }, 
    </pre>

  If the type is “calico-ipam”, you are good to go. If the IPAM is set to something else, or the 10-calico.conflist file does not exist, you cannot use this feature in your cluster. 

- Verify orchestrator support for changing the pod network CIDR

  Although Kubernetes supports changing the pod network CIDR, not all orchestrators do. For example, **OpenShift** does not support this feature as described in [`osm_cluster_network_cidr configuration`](https://docs.openshift.org/latest/install_config/install/advanced_install.html#configuring-cluster-variables). Check your orchestrator documentation to verify. 

**Recommended**

Understand the basics of [Calico IPAM]({{site.baseurl}}/networking/get-started-ip-addresses)

### How to

>**Important!** Make sure that you do the steps in the order shown; this ensures that existing pod connectivity is not affected. Also, when pods are deleted, applications may be temporarily unavailable (depending on the type of application); plan accordingly. 
{: .alert .alert-danger }

#### Change the IP pool block size

By default, the {{site.prodname}} IPAM block size for an IP pool is /26. To expand from the default size /26, lower the `blockSize` (for example /8). To shrink the `blockSize` from the default /26, raise the number (for example, /28). 

The high-level steps to follow are:

1. Add a new temporary IP pool. 
   **Note**: The new IP pool must not be within the same cluster CIDR.
1. Disable the old IP pool.
   **Note**: Disabling an IP pool only prevents new IP address allocations; it does not affect the networking of existing pods.
1. Delete pods from the old IP pool.
   This includes any new pods that may have been created with the old IP pool prior to disabling the pool.
1. Verify that new pods get an address from the new IP pool.
1. Delete the old IP pool.
1. Create a new pool with custom CIDR block within the same cluster CIDR.
1. Disable temporary IP pool.
1. Delete pods from the temporary IP pool.
1. Delete temporary IP pool

### Tutorial

In the following example, we created a Kubernetes cluster with default CIDR block size of /26. We want to shrink the block size to /28 to use the pool more efficiently.

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

Edit pool.yaml and disable this IP pool by setting: `disabled: true`

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

Next, we delete all of the existing pods from the old IP pool. (In our example, **coredns** is our only pod; for multiple pods you would trigger a deletion for all pods in the cluster.)

```
kubectl delete pod -n kube-system coredns-6f4fd4bdf-8q7zp
```
Restart all pods with just one command. 

<**WARNING!** This is disruptive and may take several minutes depending on the number of pods deployed.
{: .alert .alert-danger}

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

Next, we delete all of the existing pods from the old IP pool. (In our example, **coredns** is our only pod; for multiple pods you would trigger a deletion for all pods in the cluster.)

```
kubectl delete pod -n kube-system coredns-6f4fd4bdf-8q7zp
```
Restart all pods with just one command. 
<**WARNING!** This is disruptive and may take several minutes depending on the number of pods deployed.
{: .alert .alert-danger}

```
kubectl delete pod -A --all
```
You can validate your pods and block size are correct by running the following commands

```
kubectl get pods --all-namespaces -o wide
calicoctl ipam show --show-blocks
```
#### Step 8: Delete the temporary IP pool.

Clean up the IP pools by deleting the temporary IP pool.

```
calicoctl delete pool new-pool
```
