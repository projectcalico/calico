<!--- master only -->
> ![warning](../../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.20.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Kubernetes with Calico networking
Calico can be used as a network plugin for Kubernetes to provide connectivity and network policy in a Kubernetes cluster. 
Calico allows you to enforce fine-grained network security policy natively in Kubernetes. The video below shows a quick demonstration of Calico policy in action.

[![IMAGE ALT TEXT](http://img.youtube.com/vi/OE1n5PWtvMM/0.jpg)](http://www.youtube.com/watch?v=OE1n5PWtvMM "Calico network policy on Kubernetes")

# Getting Started
To start using Calico Networking in your existing Kubernetes cluster, check out our [integration tutorial](KubernetesIntegration.md).

To build a new Kubernetes cluster with Calico networking, try one of the following guides:

Quick-start guides:
- [CoreOS Vagrant](VagrantCoreOS.md)
- [CoreOS on GCE](GCE.md)
- [CoreOS on AWS](AWS.md)
- [Docker Compose](https://github.com/projectcalico/docker-compose-kubernetes) 

Bare-metal guides:
- [CoreOS bare-metal](https://github.com/kubernetes/kubernetes/blob/master/docs/getting-started-guides/coreos/bare_metal_calico.md)
- [Ubuntu bare-metal](https://github.com/kubernetes/kubernetes/blob/master/docs/getting-started-guides/ubuntu-calico.md)


# Requirements
- The kube-proxy must be started in `iptables` proxy mode.  This is the default as of Kubernetes v1.2.0.

# Troubleshooting 
- [Troubleshooting](Troubleshooting.md)

[![Analytics](https://calico-ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/cni/kubernetes/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
