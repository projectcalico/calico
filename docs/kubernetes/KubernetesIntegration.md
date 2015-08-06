# Integrating the Calico Network Plugin with Kubernetes

This guide will describe the configuration required to use the Calico network plugin in your Kubernetes deployment.

## Setting Up Your Environment 
   The Calico network plugin looks for three environment variables. If one is not set, it will assume a default value. If you need to override the defaults, you must set these variables in the environment of the _kubelet_ process. 

* #####ETCD_AUTHORITY
   By default, the Calico network plugin will assume that the etcd datastore is located at `<MASTER_IP>:6666`. Setting the `ETCD_AUTHORITY` variable in your environment will direct Calico to the correct IP if your cluster is set up differently.

* #####CALICOCTL_PATH
   This plugin requires access to the `calicoctl` binary. If your binary is not located at `/usr/bin/calicoctl`, set the `CALICOCTL_PATH` environment variable to the correct path.

* #####KUBE_API_ROOT
   The `KUBE_API_ROOT` environment variable specifies where the Kubernetes API resources are located, defaulting to the `<MASTER_IP>:8080/api/v1/`

## Configuring Nodes

#### Creating a Calico Node with the Network Plugin

* #####Automatic Install

   As of Calico v0.5.1, we have included a `--kubernetes` flag to the `calicoctl node` command that will automatically install the Calico Network Plugin as you spin up a Calico Node.
   ```
   sudo ETCD_AUTHORITY=<ETCD_IP>:<ETCD_PORT> calicoctl node --ip=<NODE_IP> --kubernetes
   ```
   >_Note in this example, we set the ETCD_AUTHORITY environment config for the duration of the command_

* #####Manual Install

   Alternatively, you can download the [latest release](https://github.com/Metaswitch/calico-docker/releases/latest) of the plugin binary directly from our GitHub Repo.

#### Configuring Kubelet Services
   On each of your nodes, you will need to configure the Kubelet to use the Calico Networking Plugin. This can be done by including the `--network_plugin=calico` option when starting the Kubelet. If you are using systemd to manage your services, you can add this line to the Kubelet config file (`/etc/systemd/` by default) and restart your Kubelets to begin using Calico.
