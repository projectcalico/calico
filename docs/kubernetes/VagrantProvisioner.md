<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.12.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Running the Kubernetes Vagrant provider with Calico networking
Calico can be used as a network plugin for Kubernetes, to provide connectivity for workloads in a Kubernetes cluster.

The Kubernetes Vagrant provider uses Open vSwitch networking by default, but it can also be configured to provision a local cluster with Calico networking.

## Getting Started
First, you'll need to check out a copy of the Kubernetes git repo. Currently the Calico Vagrant plugin code is waiting to be merged into the Kubernetes repo, so for now you'll need to check out our fork of the Kubernetes repo (which is based on the latest 1.0 release candidate).
```
git clone -b calico-network-plugin-dev https://github.com/Metaswitch/kubernetes.git
cd kubernetes
```

Now set the environment variables to specify the Calico Vagrant provisioner, and run the cluster init script from the root of the kubernetes repo:
```
export KUBERNETES_PROVIDER=vagrant
export NETWORK_MODE=calico
cluster/kube-up.sh
```

This will create a 2-node, 1-master cluster, with Calico providing network connectivity for Pods. As with the Open vSwitch mode, you can set the `NUM_MINIONS` environment variable to change the number of nodes that are provisioned.

## Operating the cluster
The cluster will operate as normal; from the perspective of a Pod's containers, IP connectivity is the same.

The calicoctl tool has been installed at /home/vagrant/calicoctl, so this can be used as normal to assist debugging. Note that Calico policy can be configured using calicoctl, but it is not fully supported in the Kubernetes environment; pod-to-pod policy can be enforced, but traffic to Kubernetes Services will not hit the correct policy rules. We are actively working on enhancing Kubernetes to support Calico policy with services.
