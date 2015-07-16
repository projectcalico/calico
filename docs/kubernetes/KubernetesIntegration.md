# Integrating the Calico-Kubernetes Plugin

This guide will take you through all of the configuration hooks needed to integrate the Calico-Kubernetes plugin into your cloud platform.

## Setting Up Your Environment 
   The Calico-Kubernetes plugin looks for three environment variables. If one is not set, it will assume a default value. For custom networks, you must configure these variables in the _kubelet_ environment, not the _shell_ environment. 

* #####ETCD_AUTHORITY
   By default, the Calico-Kubernetes plugin will assume that the ETCD Authority is located at the `Master IP` of your cluster at `port 6666`. Setting the `ETCD_AUTHORITY` variable in your environment will direct Calico to the correct IP if your cluster is set up differently.

* #####CALICOCTL_PATH
   This plugin requires the `calicoctl` binary. If your binary is not located at `/usr/bin/calicoctl`, you can set the `CALICOCTL_PATH` environment variable to the correct path.

* #####KUBE_API_ROOT
   The `KUBE_API_ROOT` environment variable specifies where the Kubernetes API resources are located, defaulting to the `<MASTER_IP>/api/v1/`

## Configuring Nodes

#### Creating a Calico Node with the Kubernetes Plugin

* #####Automatic Install

   With our latest distribtution of Calico, we have included a `--kubernetes` flag to the `calicoctl node` command that will automatically install the Kubernetes plugin as you spin up a Calico Node.
   ```
   sudo ETCD_AUTHORITY=<MASTER_IP> calicoctl node --ip=<NODE_IP> --kubernetes
   ```
   >_Note in this example, we embedded the ETCD_AUTHORITY environment config_

* #####Manual Install

   Alternatively, you can download the [latest release](https://github.com/Metaswitch/calico-docker/releases/latest) of the plugin binary directly from our Github Repo.
   To apply a plugin to the node, you can use the `--plugin-dir=<PLUGIN_DIR>` option of the `calicoctl node` command

#### Configuring Kubelet Services
   On each of your nodes, you will need to verify that your kubelet service config files ( `/etc/systemd/kube-kubelet.service` by default ) include a reference to the calico networking plugin. Look for/add this line to the config:
   ``` 
   --network_plugin=calico
   ```
