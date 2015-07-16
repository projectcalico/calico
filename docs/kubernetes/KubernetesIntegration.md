# Configuring the Calico-Kubernetes Plugin

This guide will show you how to integrate the Calico-Kubernetes plugin into your cloud platform.

## Setting Up Your Environment 

#### ETCD_AUTHORITY
   By default, the Calico-Kubernetes plugin will assume that the ETCD Authority is located at the `Master IP` of your cluster at `port 6666`. Setting the `ETCD_AUTHORITY` variable in your environment will direct Calico to the correct IP if your cluster is set up differently.

#### CALICOCTL_PATH
   This plugin requires the `calicoctl` binary. If your binary is not located at `/usr/bin/calicoctl`, you can set the `CALICOCTL_PATH` environment variable to the correct path.

#### KUBE_API_ROOT
   The `KUBE_API_ROOT` environment variable specifies where the Kubernetes API resources are located, defaulting to the `<MASTER_IP>/api/v1/`

## Configuring Kubernetes

#### Kube-Kubelet Services
   On each of your nodes, you will need to verify that your `kube-kublet.service` config files ( `/etc/systemd/kube-kublet.service` by default ) include a reference to the calico networking plugin. Look for/add this line:
   ``` 
   --network_plugin=calico
   ```