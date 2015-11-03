<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.10.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Integrating the Calico Network Plugin with Kubernetes

This guide will describe the configuration required to use the Calico network plugin in your Kubernetes deployment.

## Setting Up Your Environment 
   The Calico network plugin looks for five environment variables. If one is not set, it will assume a default value. If you need to override the defaults, you must set these variables in the environment of the _kubelet_ process.

* #####ETCD_AUTHORITY
   The location of the Calico etcd directory in the form `<IP>:<PORT>`
   
   Default: `kubernetes-master:6666`.

* #####KUBE_API_ROOT
   The URL for the root of the Kubernetes API. The transport must be included. 

   Default: `http://kubernetes-master:8080/api/v1/`.

* #####DEFAULT_POLICY (added in calico-kubernetes v0.2.0)
   The default [security policy](http://docs.projectcalico.org/en/latest/security-model.html) to apply to incoming pods. 
   
   Default: `allow` - allows all incoming and outgoing traffic to and from a pod. 

   Alternately, you may also specify `ns_isolation`, which will only allow incoming traffic from pods of the same namespace and allow all outgoing traffic.

* #####CALICO_IPAM (added in calico-kubernetes v0.2.0)
   Toggles Calico IP Address Management (IPAM). When set to `true`, Calico will automatically assign pods an IP address that is unique in the cluster. When `false`, pods utilize the IP address assigned by Docker.

   Default: `false`

* ##### KUBE_AUTH_TOKEN (added in calico-kubernetes v0.3.0)
   The `KUBE_AUTH_TOKEN` environment variable specifies the token to use for https authentication with the Kubernetes apiserver. Each Kubernetes Service Account has its own API token. You can create Service Accounts by following the instructions in the [Kubernetes docs](http://kubernetes.io/v1.0/docs/user-guide/service-accounts.html).

+ #####CALICOCTL_PATH
   _Deprecated in [calico-kubernetes v0.4.0](https://github.com/projectcalico/calico-kubernetes/releases/tag/v0.4.0)_

   Path to the `calicoctl` binary.

   Default: `calicoctl`

## Configuring Nodes

#### Creating a Calico Node with the Network Plugin

* #####Automatic Install

   As of Calico v0.5.1, we have included a `--kubernetes` flag to the `calicoctl node` command that will automatically install the Calico network plugin as you spin up a Calico Node.
   ```
   sudo ETCD_AUTHORITY=<ETCD_IP>:<ETCD_PORT> calicoctl node --ip=<NODE_IP> --kubernetes
   ```

* #####Manual Install

   Alternatively, you can download the [latest release](https://github.com/projectcalico/calico-docker/releases/latest) of the plugin binary directly from our GitHub Repo and place it in the kubernetes plugin directory as `/usr/libexec/kubernetes/kubelet-plugins/net/exec/calico/calico`.

#### Configuring Kubelet Services
   On each of your nodes, you will need to configure the Kubelet to use the Calico Networking Plugin. This can be done by including the `--network_plugin=calico` option when starting the Kubelet. If you are using systemd to manage your services, you can add this line to the Kubelet config file (usually `/etc/systemd/`) and restart your Kubelets to begin using Calico.

### Configuring Policy
   See our doc on [Programming Kubernetes Policy](KubernetesPolicy.md) to start enforcing security policy on Kubernetes pods.
