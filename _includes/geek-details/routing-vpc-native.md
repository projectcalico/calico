The underlying cloud VPC (virtual private network) is used to route pod traffic between nodes, and understands which pod IP address are located on which nodes. This avoids the need for an overlay, and typically has good performance characteristics. 

In addition, pod IPs are understood by the broader cloud network, so for example, VMs outside of the cluster can connect directly to a pod without going via a Kubernetes service if desired.
