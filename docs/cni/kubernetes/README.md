<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-containers source tree.
>
> View the calico-containers documentation for the latest release [here](https://github.com/projectcalico/calico-containers/blob/v0.14.0/README.md).
<!--- else
> You are viewing the calico-containers documentation for release **release**.
<!--- end of master only -->

# Kubernetes with Calico networking
Calico can be used as a network plugin for Kubernetes using the Container Network Interface to provide connectivity for workloads in a Kubernetes cluster.  Calico is particularly suitable for large Kubernetes deployments on bare metal or private clouds, where the performance and complexity costs of overlay networks can become significant. It can also be used in public clouds.

To start using Calico Networking in your existing Kubernetes cluster, check out our [integration tutorial](KubernetesIntegration.md).

To build a new Kubernetes cluster with Calico networking, try one of the following guides:

Quick-start guides:
- [CoreOS Vagrant](VagrantCoreOS.md)
- [CoreOS on GCE](GCE.md)
- [CoreOS on AWS](AWS.md)

Bare-metal guides:
- [CoreOS bare-metal](https://github.com/kubernetes/kubernetes/blob/master/docs/getting-started-guides/coreos/bare_metal_calico.md)
- [Ubuntu bare-metal](https://github.com/kubernetes/kubernetes/blob/master/docs/getting-started-guides/ubuntu-calico.md)


# Kubernetes with Calico policy
Calico can provide network policy for Kubernetes clusters.  This feature is currently experimental and disabled by default. [The policy documentation](Policy.md) explains how to enable and use Calico policy in a Kubernetes cluster.

# Requirements
- The kube-proxy should be started in `iptables` proxy mode.  Userspace mode may work for some deployments, but is not recommended. 

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-containers/docs/kubernetes/README.md?pixel)](https://github.com/igrigorik/ga-beacon)
