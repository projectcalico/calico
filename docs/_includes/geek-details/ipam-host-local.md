How Kubernetes assigns IP address to pods is determined by the IPAM (IP Address Management) plugin being used.

The Host-local IPAM plugin allocates a static range of IP addresses for each node at node creation time.  The pods on each node are then allocated IP addresses from within each node's static range.  

By default, the static range is a /24 (256 IP addresses).

For most deployments, Host-local IPAM is a simple and adequate solution. However, using a static address range per node typically means less efficient use of the available IP address space. If you are running particularly large clusters, or have  other significant enterprise address space demands, then it may be worth considering {{site.prodname}} IPAM as an alternative to provide more efficient address space management.
