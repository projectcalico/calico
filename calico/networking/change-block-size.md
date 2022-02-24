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

#### About IP pools

By default, {{site.prodname}} uses an IPAM block size of 64 addresses – /26 for IPv4, and /122 for IPv6. However, the block size can be changed depending on the IP pool address family.

- IPv4: 20-32, inclusive
- IPv6: 116-128, inclusive

You can have **only one default IP pool for per protocol** in your installation manifest. In this example, there is one IP pool for IPv4 (/26), and one IP pool for IPv6 (/122).

```
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
  pec:
   # Configures Calico networking.
   calicoNetwork:
     # Note: The ipPools section cannot be modified post-install.
    ipPools:
    - blockSize: 26
      cidr: 10.48.0.0/21
      encapsulation: IPIP
      natOutgoing: Enabled
      nodeSelector: all()
    - blockSize: 122
      cidr: 2001::00/64 
      encapsulation: None 
      natOutgoing: Enabled 
      nodeSelector: all()
``` 

However, the following is invalid because it has two IP pools for IPv4. 

```
apiVersion: operator.tigera.io/v1
kind: Installation
metadata:
  name: default
  spec:
   # Configures Calico networking.
   calicoNetwork:
     # Note: The ipPools section cannot be modified post-install.
    ipPools:
    - blockSize: 26
      cidr: 10.48.0.0/21
      encapsulation: IPIP
      natOutgoing: Enabled
      nodeSelector: all()
    - blockSize: 31
      cidr: 10.48.8.0/21
      encapsulation: IPIP
      natOutgoing: Enabled
      nodeSelector: all()

```

#### Expand or shrink IP pool block sizes

By default, the {{site.prodname}} IPAM block size for an IP pool is /26. To expand from the default size /26, lower the `blockSize` (for example, /24). To shrink the `blockSize` from the default /26, raise the number (for example, /28).

#### Best practice: change IP pool block size before installation 

Because the `blockSize` field cannot be edited directly after {{site.prodname}} installation, it is best to change the IP pool block size before installation to minimize disruptions to pod connectivity. 

### Before you begin...

**Required**

Verify that you are using {{site.prodname}} IPAM.   

{% include content/determine-ipam.md %}

### How to

>**Important!** Follow the steps in order to minimize pod connectivity disruption. Pods may lose connectivity when they are redeployed, and may lose external connectivity while in the temporary pool. Also, when pods are deleted, applications may be temporarily unavailable (depending on the type of application). Plan your changes accordingly. 
{: .alert .alert-danger}

The high-level steps to follow are:

1. [Create a temporary IP pool](#create-a-temporary-ip-pool)    
  **Note**: The temporary IP pool must not overlap with the existing one.
1. [Disable the existing IP pool](#disable-the-existing-ip-pool)    
  **Note**: When you disable an IP pool, only new IP address allocations are prevented; networking of existing pods are not affected.
1. [Delete pods from the existing IP pool](#delete-pods-from-the-existing-ip-pool)    
   This includes any new pods that may have been created with the existing IP pool prior to disabling the pool. Verify that new pods get an address from the temporary IP pool.
1. [Delete the existing IP pool](#delete-the-existing-ip-pool)
1. [Create a new IP pool with the desired block size](#create-a-new-ip-pool-with-the-desired-block-size)
1. [Disable the temporary IP pool](#disable-the-temporary-ip-pool)
1. [Delete pods from the temporary IP pool](#delete-pods-from-the-temporary-ip-pool)
1. [Delete the temporary IP pool](#delete-the-temporary-ip-pool)

### Tutorial

In the following steps, our Kubernetes cluster has a default CIDR block size of /26. We want to shrink the block size to /28 to use the pool more efficiently. 

#### Create a temporary IP pool

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

#### Disable the existing IP pool

Disable allocations in the default pool.

```
calicoctl patch ippool default-ipv4-ippool -p '{"spec": {"disabled": true}}'
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

#### Delete pods from the existing IP pool

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

#### Delete the existing IP pool

Now that you’ve verified that pods are getting IPs from the new range, you can safely delete the existing pool.

```
calicoctl delete ippool default-ipv4-ippool
```

#### Create a new IP pool with the desired block size

In this step, we update the IPPool with the new block size of (/28). 

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

#### Disable the temporary IP pool

```
calicoctl patch ippool temporary-pool -p '{"spec": {"disabled": true}}'
```

#### Delete pods from the temporary IP pool

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
#### Delete the temporary IP pool

Clean up the IP pools by deleting the temporary IP pool.

```
calicoctl delete pool temporary-pool
```
