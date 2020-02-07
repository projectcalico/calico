The CNI (Containter Network Inteface) plugin being used by Kuberenetes determines the details of exactly how pods are connected to the underlying network.

The Calico CNI plugin connects pods to the host networking using L3 routing. This is simple and easy to understand, and more efficient than alternatives such as kubenet or flannel.
