How Kubernetes assigns IP address to pods is determined by the IPAM (IP Address Management) plugin being used.

The Host-local IPAM plugin allocates a static range of IP addresses for each node as node creation time.  The pods on the node are then allocated IP addresses from within the node's static range.  

By default the static range is a /24 (256 IP addresses).
