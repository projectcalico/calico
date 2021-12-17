An overlay network allows pods to communicate between nodes without the underlying network being aware of the pods or pod IP addresses.

Packets between pods on different nodes are encapsulated using VXLAN, wrapping each original packet in an outer packet that uses node IPs, and hiding the pod IPs of the inner packet. This can be done very efficiently by the Linux kernel, but it still represents a small overhead, which you might want to avoid if running particularly network intensive workloads.

For completeness, in contrast, operating without using an overlay provides the highest performance network. The packets that leave your pods are the packets that go on the wire.
