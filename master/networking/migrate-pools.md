---
title: Migrate from one IP pool to another
---

### Big picture

Migrate pods from one IP pool to another on a running cluster without network disruption.

### Value

Pods are assigned IP addresses from IP pools that you configure in {{site.prodname}}. As pods increase, you may want pods to move a larger CIDR. Or, you may need to move pods from a CIDR that was used my mistake. {{site.prodname}} provides a way to migrate to a different IP pool on a running cluster without network disruption. 

### Features

This how-to guide uses the following Calico features:

- **IPPool** resource 

### Concepts

#### IP pools and cluster CIDRs

{{site.prodname}} supports changing IP pools for pods as long as the IP pool you are changing to is within the same cluster CIDR. Although it is technically feasible to change a pod to an IP pool outside the cluster CIDR, we do not recommend it; this requires restarting components (affects application availability), and if you change to a CIDR range that doesn’t include the already-assigned value, existing pods can lose connectivity.

### Before you begin...

- You must be using {{site.prodname}} IPAM.  
  If you are not sure, ssh to one of your Kubernetes nodes and examine the CNI configuration. 

  <pre>
  `cat /etc/cni/net.d/10-calico.conflist`
  </pre>
  Look for the "type" entry:

  <pre>
     "ipam": {
           "type": "calico-ipam"
      }, 
  </pre>

   If the type is “calico-ipam,” you are good to go. If the IPAM is set to something else, or the 10-calico.conflist file does not exist, you cannot use this feature in your cluster. 

- Although Kubernetes supports changing the pod network CIDR, not all orchestrators do. For example, OpenShift does not support this feature as described in [`osm_cluster_network_cidr configuration` field](https://docs.openshift.org/latest/install_config/install/advanced_install.html#configuring-cluster-variables). Check your orchestrator documentation to verify that it supports changing the pod CIDR. 

### How to

#### Migrate from one IP pool to another

Follow these steps to migrate pods from one IP pool to another pool in the same cluster CIDR. 

> **Important!** If you follow these steps, existing pod connectivity will not be affected. (If you delete the old IP before you create and verify the new one, existing pods will be affected.) Depending on your application, when you delete a pod, applications may be temporarily unavailable; plan accordingly. 
{: .alert .alert-danger }

1. Add a new IP pool.
1. Disable the old IP pool.  
   **Note**: Disabling an IP pool only prevents new IP address allocations; it does not affect the networking of existing pods.
1. Delete pods from the old IP pool.  
   This includes any new pods that may have been created with the old IP pool prior to disabling the pool.
1. Delete the old IP pool.
1. Verify that new pods get an address from the new IP pool.

### Tutorial

In the following example, we create a Kubernetes cluster using **kubeadm**. When we installed calico nodes in this cluster, a default IP pool was assigned: **192.168.0.0/16**. Now, we want pods in the cluster to use IPs in the CIDR: **10.0.0.0/16** (within the cluster CIDR). 

Let’s run `calicoctl get ippool -o wide` to see the default IP pool, **default-ipv4-ippool**.

```
NAME                  CIDR             NAT    IPIPMODE   VXLANMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     Never       false
```

When we run `calicoctl get wep --all-namespaces`, we see that a pod has been created using the default range (192.168.52.130/32).

```
NAMESPACE     WORKLOAD                   NODE      NETWORKS            INTERFACE
kube-system   coredns-6f4fd4bdf-8q7zp   vagrant   192.168.52.130/32   cali800a63073ed
```

Let’s get started changing this pod to the new IP pool (10.0.0.0/16).

#### Step 1: Add a new IP pool

We add a new **IPPool** with the CIDR range, **10.0.0.0/16**.

```
cat <<EOF | calicoctl apply -f -
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
name: new-pool
spec:
cidr: 10.0.0.0/16
ipipMode: Always
natOutgoing: true
EOF
```
Let’s verify our IP pools.

`calicoctl get ippool -o wide`

```
NAME                  CIDR             NAT    IPIPMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     false
new-pool              10.0.0.0/16      true   Always     false
```

#### Step 2: Disable the old IP pool

List the existing IP pool definition.

`calicoctl get ippool -o yaml > pool.yaml`

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

```
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: default-ipv4-ippool
spec:
  cidr: 192.0.0.0/16
  ipipMode: Always
  natOutgoing: true
  disabled: true
```

Apply the changes. 

Remember, disabling a pool only affects new IP allocations; networking for existing pods is not affected.

`calicoctl apply -f pool.yaml`

Verify the changes.

`calicoctl get ippool -o wide`

```
NAME                  CIDR             NAT    IPIPMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     true
new-pool              10.0.0.0/16      true   Always     false
```

#### Step 3: Delete pods from the old IP pool

Next, we delete all of the existing pods from the old IP pool. (In our example, **coredns** is our only pod, but you would repeat this command for each pod in the cluster.)

`kubectl delete pod -n kube-system coredns-6f4fd4bdf-8q7zp`

#### Step 4: Verify that new pods get an address from the new IP pool

1. Create a test namespace and nginx pod.  
   `kubectl create ns ippool-test`

1. Create an nginx pod. 
   `kubectl run --namespace=ippool-test nginx --replicas=1 --image=nginx`

1. Verify that the new pod gets an IP address from the new range.  
   `kubectl -n ippool-test get pods -l run=nginx -o wide`

1. Clean up the ippool-test namespace. 
   `kubectl delete ns ippool-test`


#### Step 5: Delete the old IP pool

Now that you've verified that pods are getting IPs from the new range, you can safely delete the old pool.

`calicoctl delete pool default-ipv4-ippool`


### Above and beyond

- [IP pools reference]({{ site.baseurl }}/{{ page.version }}/reference/resources/ippool)


HELP _____

For example, in Kubernetes, all three of the following arguments must be equal to, or contain, the Calico IP pool CIDRs:

- kube-apiserver: `--pod-network-cidr`
- kube-proxy: `--cluster-cidr`
- kube-controller-manager: `--cluster-cidr`

OpenShift does not support changing the pod network CIDR (as per their [documentation on the `osm_cluster_network_cidr` configuration field](https://docs.openshift.org/latest/install_config/install/advanced_install.html#configuring-cluster-variables).

**Application availability impact**

This process will require the recreation of all {{ site.prodname }}-networked workloads, which will have some impact on
the availability of your applications.

## Consequences of deleting an IP pool without following this migration procedure

Removing an IP pool without following this migration procedure can cause network connectivity disruptions in any running
workloads with addresses from that IP pool. Namely:

- If IP-in-IP or VXLAN was enabled on the IP pool, those workloads will no longer have their traffic encapsulated.
- If nat-outgoing was enabled on the IP pool, those workloads will no longer have their traffic NAT'd.
- If using Calico BGP routing, routes to pods will no longer be aggregated.

[the IP pools reference]({{ site.baseurl }}/{{ page.version }}/reference/resources/ippool).
