BGP (Border Gateway Protocol) is used to dynamically program routes for pod traffic between nodes.

BGP is a standards-based routing protocol used to build the internet. It scales exceptionally well, and even the largest Kubernetes clusters represent a tiny amount of load compared to what BGP can cope with.

{{site.prodname}} can run BGP in three modes:
- **Full mesh** - where each node talks BGP to each other, easily scaling to 100 nodes, on top of an underlying L2 network or using IPIP overlay
- **With route reflectors** - where each node talks to one or more BGP route reflectors, scaling beyond 100 nodes, on top of an underlying L2 network or using IPIP overlay
- **Peered with TOR (Top of Rack) routers** - in a physical data center where each node talks to routers in the top of the corresponding rack, scaling to the limits of your physical data center.

