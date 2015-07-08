# Running Kubernetes with Calico networking
Calico can be used as a network plugin for Kubernetes, to provide connectivity for workloads in a Kubernetes cluster.

Currently, the Calico network plugin for Kubernetes does not support ACL policies, but this function is in the pipeline.

## Getting Started
First, you'll need to check out a copy of the Kubernetes git repo. Currently the Calico plugin is hosted in a Metaswitch repo, but will shortly be merged upstream.
'''
git clone git@github.com:Metaswitch/calico-kubernetes.git
git checkout calico-network-plugin-dev
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

## Integration
To use the Calico network plugin on an existing Kubernetes deployment, you must perform the following steps:
 
1. Download the plugin from a [Calico release](https://github.com/Metaswitch/calico-docker/releases/download/v0.4.8/calico_kubernetes).
2. Copy the calico_kubernetes plugin binary to the path `/usr/libexec/kubernetes/kubelet-plugins/net/exec/calico/calico` on each kubernetes node in your cluster.
3. Restart the node kubelet processes with the flag `--network_plugin=calico"`.