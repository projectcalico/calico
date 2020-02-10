How Kubernetes assigns IP address to pods is determined by the IPAM (IP Address Management) plugin being used.

The AWS IPAM plugin dynamically allocates small blocks of IP addresses to nodes as required, using IP addresses from the underlying VPC (Virtual Private Cloud). The AWS IPAM plugin is used in conjunction with the Amazon VPC CNI plugin to provide VPC native pod networking.
