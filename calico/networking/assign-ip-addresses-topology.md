---
title: Assign IP addresses based on topology
description: Configure Calico to use specific IP pools for different topologies including zone, rack, or region. 
canonical_url: '/networking/assign-ip-addresses-topology'
---

### Big picture

Assign blocks of IP addresses from an IP pool for different topological areas.

### Value

If you have workloads in different regions, zones, or rack, you may want them to get IP addresses from the same IP pool. This strategy is useful for reducing the number of routes that are required in the network, or to meet requirements imposed by an external firewall device or policy. {{site.prodname}} makes it easy to do this using an IP pool resource with node labels and node selectors.

### Features

This how-to guide uses the following {{site.prodname}} features:

- **IPPool** resource

### Concepts

#### IP address assignment

Topology-based IP address assignment requires addresses to be per-host (node). 
As such, Kubernetes annotations cannot be used because annotations are only per-namespace and per-pod. And although you can configure IP addresses for nodes in the CNI configuration, you are making changes within the host’s file system. The best option is to use node-selection IP address assignment using IP pools.

#### Node-selection IP address management

Node selection-based IP address assignment is exactly what it sounds like: node labels are set, and Calico uses node selectors to decide which IP pools to use when assigning IP addresses to the node.

#### Best practice

Nodes only assign workload addresses from IP pools which select them. To avoid having a workload not get an IP and fail to start, it is important to ensure that all nodes are selected by at least one IP pool.

### How to

#### Create an IP pool, specific nodes

In the following example, we create an IP pool that only allocates IP addresses for nodes with the label, **zone=west**.

```yaml
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
   name: zone-west-ippool
spec:
   cidr: 192.168.0.0/24
   ipipMode: Always
   natOutgoing: true
   nodeSelector: zone == "west"
```

Then, we label a node with zone=west. For example:

```bash
kubectl label nodes kube-node-0 zone=west
```

### Tutorial

In this tutorial, we create a cluster with four nodes across two racks (two nodes/rack). 

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

   ```bash
   calicoctl delete ippools default-ipv4-ippool
   ```

2. Label the nodes.

   To assign IP pools to specific nodes, these nodes must be labelled
   using {% include open-new-window.html text='kubectl label' url='https://kubernetes.io/docs/tasks/configure-pod-container/assign-pods-nodes/#add-a-label-to-a-node' %}.

   ```bash
   kubectl label nodes kube-node-0 rack=0
   kubectl label nodes kube-node-1 rack=0
   kubectl label nodes kube-node-2 rack=1
   kubectl label nodes kube-node-3 rack=1
   ```

3. Create an IP pool for each rack.

   ```bash
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

   ```bash
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

   We should now have two enabled IP pools, which we can see when running `calicoctl get ippool -o wide`:

   ```
   NAME                  CIDR             NAT    IPIPMODE   DISABLED   SELECTOR
   rack-0-ippool         192.168.0.0/24   true   Always     false      rack == "0"
   rack-1-ippool         192.168.1.0/24   true   Always     false      rack == "1"
   ```
   {: .no-select-button}

4. Verify that the IP pool node selectors are being respected.

   We will create an nginx deployment with five replicas to get a workload
   running on each node.

   ```bash
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

### Above and beyond

[Calico IPAM]({{ site.baseurl }}/reference/cni-plugin/configuration)
