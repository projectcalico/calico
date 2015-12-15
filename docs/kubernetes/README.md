<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.13.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Kubernetes with Calico networking
Calico can be used as a network plugin for Kubernetes, to provide connectivity for workloads in a Kubernetes cluster.  Calico is particularly suitable for large Kubernetes deployments on bare metal or private clouds, where the performance and complexity costs of overlay networks can become significant. It can also be used in public clouds.

To start using Calico Networking in your existing Kubernetes cluster, check out our [integration tutorial](KubernetesIntegration.md).

To build a new Kubernetes cluster with Calico networking, try one of the following guides:

- [Ubuntu/systemd bare-metal](https://github.com/kubernetes/kubernetes/blob/master/docs/getting-started-guides/ubuntu-calico.md)
- [CoreOS bare-metal](https://github.com/kubernetes/kubernetes/blob/master/docs/getting-started-guides/coreos/bare_metal_calico.md)
- [Kubernetes Vagrant Saltfiles](VagrantProvisioner.md)
- [AWS Cluster Integration](AWSIntegration.md)
- [DigitalOcean + Fedora](https://github.com/kubernetes/kubernetes/blob/master/docs/getting-started-guides/fedora/fedora-calico.md)

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/kubernetes/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
