How Kubernetes assigns IP address to pods is determined by the IPAM (IP Address Management) plugin being used.

The {{site.prodname}} IPAM plugin dynamically allocates small blocks of IP addresses to nodes as required, to give efficient overall use of the available IP address space.  In addition, {{site.prodname}} IPAM supports advanced features such as multiple IP pools, the ability to specify a specific IP address range that a namespace or pod should use, or even the specific IP address a pod should use.
