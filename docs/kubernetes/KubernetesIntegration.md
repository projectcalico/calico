<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.12.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Add Calico to an Existing Kubernetes Cluster 

This guide will describe the steps required to install Calico on an existing Kubernetes cluster.

## Requirements
- An existing Kubernetes cluster running Kubernetes >= v1.0
- An `etcd` cluster accessible by all nodes in the Kubernetes cluster

## About the Calico Components

There are two components of a Calico / Kubernetes integration.
- The Calico per-node docker container, [`calico/node`](https://hub.docker.com/r/calico/node/)
- The [calico-kubernetes](https://github.com/projectcalico/calico-kubernetes) network plugin.

> In addition, Calico relies on `etcd` for a distributed data storage.  This guide does not cover configuring `etcd`.

The `calico/node` docker container must be run on the Kubernetes master and each Kubernetes node in your cluster, as it contains the BGP agent necessary for Calico routing to occur.
The `calico-kubernetes` plugin integrates directly with the Kubernetes `kubelet` process on each node to discover which pods have been created, and adds them to Calico networking.

We recommend using the latest version of [calicoctl](https://github.com/projectcalico/calico-docker/releases/latest) to install both `calico/node` and `calico-kubernetes` on each of your nodes.

## Installing Calico Componenets
#### 1. Install Calico
Each Kubernetes node requires both the `calico/node` container as well as the `calico-kubernetes` plugin.  Kubernetes masters do not need the `calico-kubernetes` plugin installed, but may do so if pods will be scheduled on the master.

The following set of commands will install both `calico/node` and the `calico-kubernetes` plugin on a machine.
```
# Download and install `calicoctl`
wget http://www.projectcalico.org/latest/calicoctl 
sudo chmod +x calicoctl

# Run the calico/node container
sudo ETCD_AUTHORITY=<ETCD_IP>:<ETCD_PORT> ./calicoctl node --kubernetes --kube-plugin-version=v0.6.1
```
> In the above commands, the `--kubernetes` option installs the `calico-kubernetes` plugin at the given version. 

#### 2. Configure the Network Plugin 
The Calico network plugin for Kubernetes uses the `calico_kubernetes.ini` file to read in user configuration.

Create a file called `calico_kubernetes.ini` in the same directory as the Calico plugin.
- Default: `/usr/libexec/kubernetes/kubelet-plugins/net/exec/calico/calico_kubernetes.ini`
- CoreOS: `/etc/kubelet-plugins/calico/calico_kubernetes.ini`

Your configuration file will look something like this:
```
[config]
ETCD_AUTHORITY=kubernetes-master:6666
KUBE_API_ROOT=https://kubernetes-master:443/api/v1/
DEFAULT_POLICY=allow
CALICO_IPAM=true
KUBE_AUTH_TOKEN=<INSERT_AUTH_TOKEN>
```
> Supported configuration options are discussed in the [configuration guide](PluginConfiguration.md).

## Configuring Kubernetes
#### Configuring the Kubelet 
Once the Calico network plugin has been installed, and the `calico/node` container started, you will need to configure the Kubelet to use the Calico network plugin when starting pods. 

The `kubelet` can be configured to use Calico by starting it with the `--network-plugin=calico` option.

On CoreOS machines, the Calico network plugin is installed to the `/etc/kubelet-plugins` directory, and so an additional flag is necessary to inform the `kubelet` of the location of the plugin.  On CoreOS, include the `--network-plugin-dir=/etc/kubelet-plugins` option when starting the `kubelet`.
> Note: the `--network-plugin-dir=` option is only available in Kubernetes >= v1.1.0

#### Configuring the Kube-Proxy
In order to use Calico policy with Kubernetes, the `kube-proxy` component must be configured to leave the source address of service bound traffic intact.  This feature is first officially supported in Kubernetes v1.1.0.

There are two ways to enable this behavior.
- Option 1: Start the `kube-proxy` with the `--proxy-mode=iptables` option.
- Option 2: Annotate the Kubernetes Node API object with `net.experimental.kubernetes.io/proxy-mode` set to `iptables`.
[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/kubernetes/KubernetesIntegration.md?pixel)](https://github.com/igrigorik/ga-beacon)
