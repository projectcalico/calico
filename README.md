## Calico Network Policy for Kubernetes 

This repository contains the Calico Kubernetes policy controller, which implements the Kubernetes network policy API.  The controller uses the Kubernetes v1beta1 network policy API to configure Calico network policy.  The controller is run on each Kubernetes master as a [static pod](examples/policy-controller.yaml).

To use the v1beta1 API, you must be running Kubernetes v1.3, with the following `apiserver` runtime configuration to enable it:
```
--runtime-config=extensions/v1beta1,extensions/v1beta1/networkpolicies
```

See the documentation on [network policy in Kubernetes](http://kubernetes.io/docs/user-guide/networkpolicies/) for more information on how to use NetworkPolicy. 
