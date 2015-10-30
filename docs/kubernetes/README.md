<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.9.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Kubernetes with Calico networking
Calico can be used as a network plugin for Kubernetes, to provide connectivity for workloads in a Kubernetes cluster.

Calico is particularly suitable for large Kubernetes deployments on bare metal or private clouds, where the performance and complexity costs of overlay networks can become significant. It can also be used in public clouds.
To start using Calico Networking in Kubernetes, check out our [Integration Doc](https://github.com/projectcalico/calico-docker/tree/master/docs/kubernetes/KubernetesIntegration.md)

The following configuration guides have been written:

- [Kubernetes Vagrant Saltfiles](https://github.com/projectcalico/calico-docker/tree/master/docs/kubernetes/VagrantProvisioner.md)
- [Ubuntu bare-metal](https://github.com/kubernetes/kubernetes/blob/master/docs/getting-started-guides/ubuntu-calico.md)
- [CoreOS bare-metal](https://github.com/GoogleCloudPlatform/kubernetes/blob/master/docs/getting-started-guides/coreos/bare_metal_calico.md)
- [AWS Cluster Integration](https://github.com/projectcalico/calico-docker/tree/master/docs/kubernetes/AWSIntegration.md)

Coming soon:

- Digital Ocean
