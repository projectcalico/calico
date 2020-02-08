The CNI (Containter Network Inteface) plugin being used by Kuberenetes determines the details of exactly how pods are connected to the underlying network.

Kubenet combines an L2 Bridge CNI plugin with Host-local IPAM.  The result is a pod network with a combination of L2 and L3 segments, and relies on some other controller to manage the routing of pod traffic between nodes.  Often this is done by adding static routes per node at node creation time. 

Note a Kubenet based network is slightly less efficient than Calico CNI's pure L3 network.
