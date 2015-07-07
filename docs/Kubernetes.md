# Running Kubernetes with Calico networking
Calico can be used as a network plugin for Kubernetes, to provide connectivity for workloads in a Kubernetes cluster.

Currently, the Calico network plugin for Kubernetes does not support ACL policies, but this function is in the pipeline.

## Getting Started
First, you'll need to check out a copy of the Kubernetes git repo. Currently the Calico plugin is hosted in a Metaswitch repo, but will shortly be merged upstream.
'''
git clone git@github.com:Metaswitch/calico-kubernetes.git
'''

Now set the environment variables to specify the Calico Vagrant provisioner, and run the cluster init script from the root of the kubernetes repo:
'''
export KUBERNETES_PROVIDER=vagrant
export NETWORK_MODE=calico
cluster/kube-up.sh
'''

This will create a 2-node, 1-master cluster, with Calico providing network connectivity for Pods.

## Operating the cluster
The cluster will operate as normal; from the perspective of a Pod's containers, IP connectivity is the same.

The calicoctl tool has been installed at /home/vagrant/calicoctl, so this can be used as normal to assist debugging.

