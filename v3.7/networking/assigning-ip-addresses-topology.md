---
title: Assigning IP addresses based on topology
redirect_from: latest/networking/assigning-ip-addresses-topology
canonical_url: 'https://docs.projectcalico.org/v3.7/networking/assigning-ip-addresses-topology'
---

## About IP address assignment

{{site.prodname}} can be configured to use specific IP pools for different
topological areas. For example, you may want workloads in a particular rack,
zone, or region to receive addresses from the same IP pool. This may be
desirable either to reduce the number of routes required in the network or to
meet requirements imposed by an external firewall device or policy.

There are three approaches to configuring IP address assignment behavior which
the [IPAM section of the cni-plugin configuration reference
document]({{site.baseurl}}/{{page.version}}/reference/cni-plugin/configuration#ipam)
explains in detail. For the purposes of topology, IP address
assignment must be per-host (node) which disqualifies Kubernetes annotations
as an option since it is only configurable on a per-namespace or per-pod level.
Left between using CNI configuration and IP pool node selectors, the
latter is preferred as it does not require making any changes within the
host's file system which the former does.

At a high level, node selection-based IP address assignment is exactly what it
sounds like: node labels are set and then the appropriate node selectors
on the desired IP pool resources are set. The remainder of this article goes
into a detailed example of using this feature to configure IP address
assignment based on a certain rack affinity.

> **Important**: If Calico is unable to determine an IP pool for a workload
> based on the above order, or if there are no IP addresses left in the
> determined IP pools, then the workload will not be assigned an address and
> will fail to start. To prevent this, we recommend ensuring that all nodes are
> selected by at least one IP pool.
{: .alert .alert-danger}

## Prerequisites

This feature requires {{site.prodname}} for networking in etcd mode.

### Example: Kubernetes

In this example, we created a cluster with four nodes across two racks
(two nodes/rack). Consider the following:

```
       -------------------
       |    router       |
       -------------------
       |                 |
---------------   ---------------
| rack-0      |   | rack-1      |
---------------   ---------------
| kube-node-0 |   | kube-node-2 |
- - - - - - - -   - - - - - - - -
| kube-node-1 |   | kube-node-3 |
- - - - - - - -   - - - - - - - -
```
{: .no-select-button}

Using the pod IP range `192.168.0.0/16`, we target the following setup: reserve
the `192.168.0.0/24` and `192.168.1.0/24` pools for `rack-0`, `rack-1`. Let's
get started.


By installing {{ site.prodname }} without setting the default IP pool to match,
running `calicoctl get ippool -o wide` shows that {{site.prodname}} created its
default IP pool of `192.168.0.0/16`:

```
NAME                  CIDR             NAT    IPIPMODE   DISABLED   SELECTOR
default-ipv4-ippool   192.168.0.0/16   true   Always     false      all()
```
{: .no-select-button}

1. Delete the default IP pool.

   Since the `default-ipv4-ippool` IP pool resource already exists and accounts
   for the entire `/16` block, we will have to delete this first:

   ```
   calicoctl delete ippools default-ipv4-ippool
   ```

2. Label the nodes.

   To assign IP pools to specific nodes, these nodes must be labelled
   using [kubectl label](https://kubernetes.io/docs/tasks/configure-pod-container/assign-pods-nodes/#add-a-label-to-a-node).

   ```
   kubectl label nodes kube-node-0 rack=0
   kubectl label nodes kube-node-1 rack=0
   kubectl label nodes kube-node-2 rack=1
   kubectl label nodes kube-node-3 rack=1
   ```

3. Create an IP pool for each rack.

   ```
   calicoctl create -f -<<EOF
   apiVersion: projectcalico.org/v3
   kind: IPPool
   metadata:
     name: rack-0-ippool
   spec:
     cidr: 192.168.0.0/24
     ipipMode: Always
     natOutgoing: true
     nodeSelector: rack == "0"
EOF
   ```

   ```
   calicoctl create -f -<<EOF
   apiVersion: projectcalico.org/v3
   kind: IPPool
   metadata:
     name: rack-1-ippool
   spec:
     cidr: 192.168.1.0/24
     ipipMode: Always
     natOutgoing: true
     nodeSelector: rack == "1"
EOF
   ```

   We should now have two enabled IP pools, which we can see when running
   `calicoctl get ippool -o wide`:

   ```
   NAME                  CIDR             NAT    IPIPMODE   DISABLED   SELECTOR
   rack-1-ippool         192.168.0.0/24   true   Always     false      rack == "0"
   rack-2-ippool         192.168.1.0/24   true   Always     false      rack == "1"
   ```
   {: .no-select-button}

4. Verify that the IP pool node selectors are being respected.

   We will create an nginx deployment with five replicas to get a workload
   running on each node.

   ```
   kubectl run nginx --image nginx --replicas 5
   ```

   Check that the new workloads now have an address in the proper IP pool
   allocated for the rack that the node is on with `kubectl get pods -owide`.

   ```
   NAME                   READY   STATUS    RESTARTS   AGE    IP             NODE          NOMINATED NODE   READINESS GATES
   nginx-5c7588df-prx4z   1/1     Running   0          6m3s   192.168.0.64   kube-node-0   <none>           <none>
   nginx-5c7588df-s7qw6   1/1     Running   0          6m7s   192.168.0.129  kube-node-1   <none>           <none>
   nginx-5c7588df-w7r7g   1/1     Running   0          6m3s   192.168.1.65   kube-node-2   <none>           <none>
   nginx-5c7588df-62lnf   1/1     Running   0          6m3s   192.168.1.1    kube-node-3   <none>           <none>
   nginx-5c7588df-pnsvv   1/1     Running   0          6m3s   192.168.1.64   kube-node-2   <none>           <none>
   ```
   {: .no-select-button}

   The grouping of IP addresses assigned to the workloads differ based on what
   node that they were scheduled to. Additionally, the assigned address for
   each workload falls within the respective IP pool that selects the rack that
   they run on.

> **Note**: {{site.prodname}} IPAM will not reassign IP addresses to workloads
> that are already running. To update running workloads with IP addresses from
> a newly configured IP pool, they must be recreated. We recommend doing this
> before going into production or during a maintenance window.
{: .alert .alert-info}

## Related links

For more information on the structure of the IP pool resource, see
[the IP pools reference]({{ site.baseurl }}/{{ page.version }}/reference/calicoctl/resources/ippool).
