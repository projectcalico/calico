Kubernetes network policies are implemented by network plugins rather than Kubernetes itself. Simply creating a network policy resource without a network plugin to implement it, will have no effect on network traffic.

The Calico plugin implements the full set of Kubernetes network policy features. In addition, Calico supports Calico network policies, providing additional features and capabilites beyond Kubernetes network policies.  Kubernetes and Calico network policies work together seemlessly, so you can choose whichever is right for you, and mix and match as desired.
