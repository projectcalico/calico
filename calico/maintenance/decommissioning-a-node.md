---
title: Decommission a node
description: Manually remove a node from a cluster that is installed with Calico.
canonical_url: '/maintenance/decommissioning-a-node'
---

### About decommissioning nodes

If you are running the [node controller]({{ site.baseurl }}/reference/kube-controllers/configuration)
or using the Kubernetes API datastore in policy-only mode, you do not need to manually decommission nodes.

In other configurations, you may need to manually decommission a node for one
of the following reasons.

- You are decommissioning a host running `{{site.nodecontainer}}` or removing it from your
  cluster.
- You are renaming a node.
- You are receiving an error about an IP address already in use.
- Readiness checks are failing due to unreachable peers that are no longer in the
  cluster.
- Hosts are regularly added and removed from your cluster.

### Purpose of this page

Provide guidance on how to remove a host that is part of a {{site.prodname}} cluster
and clean up the associated [Node resource][Node resource reference]
information.

### Prerequisites

- Prior to removing any Node resource from the datastore the `{{site.nodecontainer}}`
  container should be stopped on the corresponding host and it should be
  ensured that it will not be restarted.
- You must have [calicoctl configured][calicoctl setup] and operational to run
  the commands listed here.

### Removing a node resource

Removing a Node resource will also remove the Workload Endpoint, Host
Endpoint, and IP Address resources and any other sub configuration items
associated with that Node.

> **Important**
> - Deleting a Node resource may be service impacting if the host is still in
  service. Ensure that the host is no longer in service before deleting the
  Node resource.
> - Any configuration specific to the node will be removed. This would be
  configuration like node BGP peerings or custom Felix configs.
{: .alert .alert-danger}

### Removing a single node resource

See the example below for how to remove a node with the calicoctl command.

> **Caution** See [Removing a Node resource](#removing-a-node-resource) above.
{: .alert .alert-danger}

```bash
calicoctl delete node <nodeName>
```

### Removing multiple node resources

To remove several Nodes, a file can be created with several Node resources and
then be passed to the `calicoctl delete` command with the `-f` flag.
Below is an example of how to create a file of Nodes and delete them.

1. Create a file with the [Node resources][Node resource reference] that need
   to be removed.  For example:

   ```yaml
   - apiVersion: projectcalico.org/v3
     kind: Node
     metadata:
       name: node-02
   - apiVersion: projectcalico.org/v3
     kind: Node
     metadata:
       name: node-03
   ```

2. To delete the nodes listed in the file pass it like below.

   > **Caution** See [Removing a Node resource](#removing-a-node-resource) above.
   {: .alert .alert-danger}

   ```bash
   calicoctl delete -f nodes_to_delete.yaml
   ```

[Node resource reference]: {{ site.baseurl }}/reference/resources/node
[calicoctl setup]: ../maintenance/clis/calicoctl/install
