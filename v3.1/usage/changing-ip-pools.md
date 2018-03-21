---
title: Changing IP pools
---

## About changing IP pools

When using {{ site.prodname }} IPAM, each workload is assigned an address from the selection of configured IP pools.
You may want to modify the IP pool of a running cluster for one of the following reasons:
- To move to a larger CIDR that can accommodate more workloads.
- To move off of a CIDR that was used accidentally.

### Purpose of this page

Provide guidance on how to change from one IP pool to another on a running cluster.

## Prerequisites

**{{site.prodname}} IPAM**

This guide only applies if you are using {{site.prodname}} IPAM.

**Orchestrator support**

While {{ site.prodname }} supports changing IP pools, not all orchestrators do.
Be sure to consult the documentation of the orchestrator you are using to ensure it supports changing the workload CIDR.

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

- If IP-in-IP was enabled on the IP pool, those workloads will no longer have their traffic encapsulated.
- If nat-outgoing was enabled on the IP pool, those workloads will no longer have their traffic NAT'd.
- If using Calico BGP routing, routes to pods will no longer be aggregated.

## Changing an IP pool

The basic process is as follows:

1. Add a new IP pool.
2. Disable the old IP pool. This prevents new IPAM allocations from the old IP pool without affecting the networking of existing workloads.
3. Recreate all existing workloads that were assigned an address from the old IP pool.
4. Remove the old IP pool.

### Example: Kubernetes

In this example, we created a cluster with kubeadm.  We wanted the pods to use IPs in the range
`10.0.0.0/16` so we set `--pod-network-cidr=10.0.0.0/16` when running `kubeadm init`.  However, we
installed {{ site.prodname }} without setting the default IP pool to match. Running `calicoctl get ippool -o wide` shows
{{site.prodname}} created its default IP pool of `192.168.0.0/16`:

```
NAME                  CIDR             NAT    IPIPMODE   DISABLED
default-ipv4-ippool   192.168.0.0/16   true   Always     false
```

Based on the output of `calicoctl get wep --all-namespaces`, we see `kube-dns` has already been allocated an address
from the wrong range:

```
NAMESPACE     WORKLOAD                   NODE      NETWORKS            INTERFACE
kube-system   kube-dns-6f4fd4bdf-8q7zp   vagrant   192.168.52.130/32   cali800a63073ed
```

Let's get started.

1. Add a new IP pool:

   ```
   calicoctl create -f -<<EOF
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

   We should now have two enabled IP pools, which we can see when running `calicoctl get ippool -o wide`:

   ```
   NAME                  CIDR             NAT    IPIPMODE   DISABLED
   default-ipv4-ippool   192.168.0.0/16   true   Always     false
   new-pool              10.0.0.0/16      true   Always     false
   ```

2. Disable the old IP pool.

   First save the IP pool definition to disk:

       calicoctl get ippool -o yaml > pool.yaml

   `pool.yaml` should look like this:

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

   >Note: Some extra cluster-specific information has been redacted to improve
   readibility.

   Edit the file, adding `disabled: true` to the `default-ipv4-ippool` IP pool:

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

   Apply the changes:

       calicoctl apply -f pool.yaml

   We should see the change reflected in the output of `calicoctl get ippool -o wide`:

   ```
   NAME                  CIDR             NAT    IPIPMODE   DISABLED
   default-ipv4-ippool   192.168.0.0/16   true   Always     true
   new-pool              10.0.0.0/16      true   Always     false
   ```

3. Recreate all existing workloads using IPs from the disabled pool. 
   In this example, kube-dns is the only workload networked by {{ site.prodname }}:

   ```
   kubectl delete pod -n kube-system kube-dns-6f4fd4bdf-8q7zp
   ```

   Check that the new workload now has an address in the new IP pool by running `calicoctl get wep --all-namespaces`:

   ```
   NAMESPACE     WORKLOAD                   NODE      NETWORKS            INTERFACE
   kube-system   kube-dns-6f4fd4bdf-8q7zp   vagrant   10.0.24.8/32   cali800a63073ed
   ```

4. Delete the old IP pool:

   ```
   calicoctl delete pool default-ipv4-ippool
   ```

## Next Steps

For more information on the structure of the IP pool resource, see
[the IP pools reference]({{ site.baseurl }}/{{ page.version }}/reference/calicoctl/resources/ippool).
