How Kubernetes assigns IP address to pods is determined by the IPAM (IP Address Management) plugin being used.

The Azure IPAM plugin dynamically allocates small blocks of IP addresses to nodes as required, using IP addresses from the underlying VNET (Virtual Network). The Azure IPAM plugin is used in conjunction with the Azure CNI plugin to provide VPC native pod networking.
