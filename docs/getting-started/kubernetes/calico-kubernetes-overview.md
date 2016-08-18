---
title: Overview of Kubernetes with Calico Networking
---

# Kubernetes with Calico networking
Calico can be used as a network plugin for Kubernetes to provide connectivity and network policy in a Kubernetes cluster. 
Calico allows you to enforce fine-grained network security policy natively in Kubernetes. The video below shows a quick demonstration of Calico policy in action.

[![IMAGE ALT TEXT](http://img.youtube.com/vi/OE1n5PWtvMM/0.jpg)](http://www.youtube.com/watch?v=OE1n5PWtvMM "Calico network policy on Kubernetes")

# Getting Started
To start using Calico Networking in your existing Kubernetes cluster, check out our [integration tutorial](KubernetesIntegration).

An easy way to try out Calico network policy on Kubernetes is by following the [stars demo](stars-demo/demonstrating-policy-kubernetes).

To build a new Kubernetes cluster with Calico networking, try one of the following guides:

Quick-start guides:

- [CoreOS Vagrant](VagrantCoreOS)
- [CoreOS on GCE](GCE)
- [CoreOS on AWS](AWS)
- [Docker Compose](https://github.com/projectcalico/docker-compose-kubernetes) 

Bare-metal guides:

- [CoreOS bare-metal](http://kubernetes.io/docs/getting-started-guides/coreos/bare_metal_calico/)
- [Ubuntu bare-metal](http://kubernetes.io/docs/getting-started-guides/ubuntu-calico/)


# Requirements
- The kube-proxy must be started in `iptables` proxy mode.  This is the default as of Kubernetes v1.2.0.

# Troubleshooting 
- [Troubleshooting](Troubleshooting-Calico-Kubernetes)

