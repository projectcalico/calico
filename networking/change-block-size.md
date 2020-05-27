---
title: Change IP pool block size
description: Expand or shrink the IP pool block size to efficiently manage IP pool addresses. 
---

### Big picture

Change the IP pool block size to efficiently manage IP pool addresses. 

### Value

Changing IP pool block size after installation requires ordered steps to minimize pod connectivity disruption. 

### Features

This how-to guide uses the following {{site.prodname}} features:

- **IPPool** resource with `blockSize` field

### Concepts

#### Expand or shrink IP pool block sizes

By default, the {{site.prodname}} IPAM block size for an IP pool is /26. To expand from the default size /26, lower the `blockSize` (for example, /24). To shrink the `blockSize` from the default /26, raise the number (for example, /28). 

#### Best practice: change IP pool block size before installation 

Because the `blockSize` field cannot be edited directly after {{site.prodname}} installation, it is best to change the IP pool block size before installation to minimize disruptions to pod connectivity. 

### Before you begin...

**Required**

- Verify that you are using {{site.prodname}} IPAM.   
  This guide is relevant only if you are using Calico IPAM.

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

### How to

>**Important!** Follow the steps in order to minimize pod connectivity disruption. Pods may lose connectivity when they are redeployed, and may lose external connectivity while in the temporary pool. Also, when pods are deleted, applications may be temporarily unavailable (depending on the type of application). Plan your changes accordingly. 
{: .alert .alert-danger}

The high-level steps to follow are:

1. [Create a temporary IP pool](#create-a-temporary-ip-pool)    
  **Note**: The temporary IP pool must not overlap with the old one.
1. [Disable the old IP pool](#disable-the-old-ip-pool)    
  **Note**: When you disable an IP pool, only new IP address allocations are prevented; networking of existing pods are not affected.
1. [Delete pods from the old IP pool](#ddelete-pods-from-the-old-ip-pool)    
   This includes any new pods that may have been created with the old IP pool prior to disabling the pool. Verify that new pods get an address from the temporary IP pool.
1. [Delete the old IP pool](#delete-the-old-ip-pool)
1. [Create a new IP pool with the desired block size](#create-a-new-ip-pool-with-the-desired-block-size)
1. [Disable the temporary IP pool](#disable-the-temporary-ip-pool)
1. [Delete pods from the temporary IP pool](#delete-pods-from-the-temporary-ip-pool)
1. [Delete the temporary IP pool](#delete-the-temporary-ip-pool)

### Tutorial

In the following steps, our Kubernetes cluster has a default CIDR block size of /26. We want to shrink the block size to /28 to use the pool more efficiently. 

#### Step 1: Create a temporary IP pool

We add a new IPPool with the CIDR range, 10.0.0.0/16.

Create a temporary-pool.yaml.

<pre>
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: temporary-pool
spec:
  cidr: 10.0.0.0/16
  ipipMode: Always
  natOutgoing: true
</pre>

Apply the changes.

```
calicoctl apply -f temporary-pool.yaml
```

Let’s verify the temporary IP pool.

```
calicoctl get ippool -o wide
```

<pre>
NAME                  CIDR             NAT    IPIPMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     false
temporary-pool        10.0.0.0/16      true   Always     false
</pre>

#### Step 2: Disable the old IP pool

List the existing IP pool definition.

```
calicoctl patch ippool default-ipv4-ippool -p '{"spec": {"disabled": “true”}}'
```

Verify the changes.

```
calicoctl get ippool -o wide
```

<pre>
NAME                  CIDR             NAT    IPIPMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     true
temporary-pool        10.0.0.0/16      true   Always     false
</pre>

#### Step 3: Delete pods from the old IP pool

In our example, **coredns** is our only pod; for multiple pods you would trigger a deletion for all pods in the cluster.

```
kubectl delete pod -n kube-system coredns-6f4fd4bdf-8q7zp
```
Restart all pods with just one command. 

 >**WARNING!** The following command is disruptive and may take several minutes depending on the number of pods deployed.
{: .alert .alert-danger}

```
kubectl delete pod -A --all
```

#### Step 4: Delete the old IP pool

Now that you’ve verified that pods are getting IPs from the new range, you can safely delete the old pool.

```
calicoctl delete ippool default-ipv4-ippool
```

#### Step 5: Create a new IP pool with the desired block size

In this step, we update the IPPool to the new block size of (/28).

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

#### Step 6: Disable the temporary IP pool

```
calicoctl patch ippool temporary-pool -p '{"spec": {"disabled": “true”}}'
```

#### Step 7: Delete pods from the temporary IP pool

In our example, **coredns** is our only pod; for multiple pods you would trigger a deletion for all pods in the cluster.

```
kubectl delete pod -n kube-system coredns-6f4fd4bdf-8q7zp
```

Restart all pods with just one command.  

 >**WARNING!** The following command is disruptive and may take several minutes depending on the number of pods deployed.
{: .alert .alert-danger}

```
kubectl delete pod -A --all
```
Validate your pods and block size are correct by running the following commands:

```
kubectl get pods --all-namespaces -o wide
calicoctl ipam show --show-blocks
```
#### Step 9: Delete the temporary IP pool

Clean up the IP pools by deleting the temporary IP pool.

```
calicoctl delete pool temporary-pool
```
