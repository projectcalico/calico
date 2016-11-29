## Kubernetes manifests for FV tests.

These manifests are used by the hyperkube image for the FV tests to run 
a single node Kubernetes cluster.

They are essentially the same as the ones that ship in the hyperkube image,
but have removed the ServiceAccount admission controller.  Mounting these
files rather than using the default allows us to get finer-grained control
of the cluster we're testing against.
