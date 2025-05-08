# IPAM Hammer

This is a simple tool to run against a cluster to stress test the IPAM garbage collection logic in the face of a large number of Node deletions.

The tool:

- Creates a configurable amount of Nodes.
- Assigns IP addresses to each of the nodes.
- Deletes all of the nodes.

This should trigger the IPAM GC logic in kube-controllers.
