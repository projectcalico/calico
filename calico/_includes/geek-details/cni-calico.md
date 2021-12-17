The CNI (Container Network Interface) plugin being used by Kubernetes determines the details of exactly how pods are connected to the underlying network.

The {{site.prodname}} CNI plugin connects pods to the host networking using L3 routing, without the need for an L2 bridge. This is simple and easy to understand, and more efficient than other common alternatives such as kubenet or flannel.
