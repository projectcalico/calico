---
title: Decommissioning a Node
canonical_url: 'https://docs.projectcalico.org/v3.3/usage/decommissioning-a-node'
---

### Why you might be interested in this guide

- You are decomissioning a host running calico/node or removing it from your
  cluster.
- You are renaming a Node.
- You are receiving an error about an IP address already in use.
- Hosts are regularly added and removed from your cluster.

### Purpose of this page

Provide guidance on how to remove a host that is part of a Calico cluster
and clean up the associated [Node resource][Node resource reference]
information.

### Prerequisites

- Prior to removing any Node resource from the datastore the calico/node
  container should be stopped on the corresponding host and it should be
  ensured that it will not be restarted.
- You must have [calicoctl configured][calicoctl setup] and operational to run
  the commands listed here.

### Removing a Calico Node resource

**Note:**
Removing a Node resource will also remove the Workload Endpoint, Host
Endpoint, and IP Address resources and any other sub configuration items
associated with that Node.

**Warning**
- Deleting a Node resource may be service impacting if the host is still in
  service.  Ensure that the host is no longer in service before deleting the
  Node resource.
- Any configuration specific to the node will be removed.  This would be
  configuration like node BGP peerings or custom Felix configs.

### Removing a single Calico Node resource

See the example below for how to remove a node with the calicoctl command.

**Caution** See the [Warning](#removing-a-calico-node-resource) above

```
calicoctl delete node <nodeName>
```

### Removing multiple Calico Node resources

To remove several Nodes, a file can be created with several Node resources and
then be passed to the `calicoctl delete` command with the `-f` flag.
Below is an example of how to create a file of Nodes and delete them.

1. Create a file with the [Node resources][Node resource reference] that need
   to be removed.  For example:

   ```
   - apiVersion: v1
     kind: node
     metadata:
       name: node-02
   - apiVersion: v1
     kind: node
     metadata:
       name: node-03
   ```

2. To delete the nodes listed in the file pass it like below.

   **Caution** See the [Warning](#removing-a-calico-node-resource) above

   ```
   calicoctl delete -f nodes_to_delete.yaml
   ```

[Node resource reference]: {{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/node
[calicoctl setup]: {{site.baseurl}}/{{page.version}}/usage/calicoctl/install-and-configuration
