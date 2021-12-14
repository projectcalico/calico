With {{site.prodname}}'s cross-subnet VXLAN mode, traffic between pods on the same subnet does not use an overlay, while traffic between pods on different subnets will go via an VXLAN overlay. 

Packets between pods on nodes within the same subnet, are sent without using an overlay to give the best possible network performance.

Packets between pods on nodes in different subnets are encapsulated using IPIP, wrapping each original packet in an outer packet that uses node IPs, and hiding the pod IPs of the inner packet. This can be done very efficiently by the Linux kernel, but it still represents a small overhead compared to non-overlay traffic.
