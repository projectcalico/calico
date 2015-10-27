<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.10.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Add Calico to an Existing Kubernetes Cluster 

This guide will describe the steps required to install Calico on an existing Kubernetes cluster.

## Requirements
- An existing Kubernetes cluster running Kubernetes >= v1.0
- An `etcd` cluster accessible by all nodes in the Kubernetes cluster

## Calico Components

There are two components of a Calico / Kubernetes integration.
- The Calico per-node docker container, `calico/node`
- The [calico-kubernetes](https://github.com/projectcalico/calico-kubernetes) network plugin.

> In addition, Calico relies on `etcd` for a distributed data storage.  This guide does not cover configuring `etcd`.

The `calico/node` docker container must be run on the Kubernetes master and each Kubernetes node in your cluster, as it contains the BGP agent necessary for Calico routing to occur.
The `calico-kubernetes` plugin integrates directly with the Kubernetes `kubelet` process on each node to discover which pods have been created, and adds them to Calico networking.

We recommend using the latest version of [calicoctl](https://github.com/projectcalico/calico-docker/releases) to install both `calico/node` and `calico-kubernetes` on each of your nodes.

## Installing Calico on a Kubernetes Master
The Kubernetes master does not run any pods itself, and so does not typically require the `calico-kubernetes` plugin.  It does require the `calico/node` docker container so that individual pod IPs can be learned over BGP.

The following set of commands will install `calico/node` on a Kubernetes master: 
```
# Download and install `calicoctl`
wget https://github.com/projectcalico/calico-docker/releases/download/v0.9.0/calicoctl 
sudo chmod +x calicoctl

# Run the calico/node container
sudo ETCD_AUTHORITY=<ETCD_IP>:<ETCD_PORT> ./calicoctl node
```
> For more information on running `calicoctl node`, please see the [`calicoctl` node documentation](https://github.com/projectcalico/calico-docker/blob/master/docs/calicoctl/node.md)

## Installing Calico on a Kubernetes Node

#### Installing the Calico Components
The Kubernetes node requires both the `calico/node` container as well as the `calico-kubernetes` plugin.

The following set of commands will install these components on a Kubernetes node:
```
# Download and install `calicoctl`
wget https://github.com/projectcalico/calico-docker/releases/download/v0.9.0/calicoctl 
sudo chmod +x calicoctl

# Run the calico/node container
sudo ETCD_AUTHORITY=<ETCD_IP>:<ETCD_PORT> ./calicoctl node --kubernetes
```
> The `--kubernetes` option installs the `calico-kubernetes` plugin appropriate for the given version of `calicoctl`.  You can use the `--kube-plugin-version` option to specify an exact version of the `calico-kubernetes` plugin to install.

#### Configuring the Kubelet 
Once the Calico network plugin has been installed, and the `calico/node` container started, you will need to configure the Kubelet to use the Calico network plugin when starting pods. 

The `kubelet` can be configured to use Calico by starting it with the `--network-plugin=calico` option.

On CoreOS machines, the Calico network plugin is installed to the `/etc/kubelet-plugins` directory, and so an additional flag is necessary to inform the `kubelet` of the location of the plugin.  On CoreOS, include the `--network-plugin-dir=/etc/kubelet-plugins` option when starting the `kubelet`.
> Note: the `--network-plugin-dir=` option is only available in Kubernetes >= v1.1.0

In addition to specifying the location of the plugin, you'll need to configure the Calico network plugin via the `kubelet` environment. Supported options can be found in the documentation on [network plugin configuration](PluginConfiguration.md).

To configure these options, it is recommended to start the `kubelet` via a process manager such as `systemd`, passing an environment file which contains the desired configuration options.

#### Configuring the Kube-Proxy
In order to use Calico policy with Kubernetes, the `kube-proxy` component must be configured to leave the source address of service bound traffic intact.  This feature is first officially supported in Kubernetes v1.1.0.

There are two ways to enable this behavior.
- Option 1: Start the `kube-proxy` with the `--proxy-mode=iptables` option.
- Option 2: Annotate the Kubernetes Node API object with `net.experimental.kubernetes.io/proxy-mode` set to `iptables`.
