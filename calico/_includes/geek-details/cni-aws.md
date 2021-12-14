The CNI (Container Network Interface) plugin being used by Kubernetes determines the details of exactly how pods are connected to the underlying network.

The AWS Amazon VPC CNI and IPAM plugins provide pods with IP addresses from the underlying VPC (Virtual Private Cloud) to provide a VPC-Native pod network. The AWS VPC is used to route pod traffic between nodes, and understands which pod IP address are located on which nodes. This avoids the need for an overlay, and typically has good network performance characteristics.

In addition, pod IPs are understood by the broader AWS network, so for example, VMs outside of the cluster can connect directly to any pod without going via a Kubernetes service if desired.
