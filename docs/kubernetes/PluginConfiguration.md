<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.12.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Configuring the Calico Kubernetes Plugin

The Calico network plugin is configurable using the following variables. Each variable assumes a default value, but can
be overridden by the user.

These variables can be specified in one of two ways:
- A configuration file named `calico_kubernetes.ini` in the same directory as the plugin.
- In the environment of the `kubelet` process.

If a variable is defined in both the configuration file and the kubelet, the value in the kubelet's environment will be
preferred.

* #####ETCD_AUTHORITY (added in calico-kubernetes v0.1.0)
   The location of the Calico `etcd` datastore in the form `<IP>:<PORT>`.
   
   Default: `localhost:2379`.

* #####KUBE_API_ROOT (added in calico-kubernetes v0.1.0)
   The URL for the root of the Kubernetes API. The transport must be included. 

   Default: `http://kubernetes-master:8080/api/v1/`.

* #####DEFAULT_POLICY (added in calico-kubernetes v0.2.0)
   The default security policy to apply to newly created pods when no annotation based policy has been defined. 

   Possible values:
    - `allow`: allows all incoming and outgoing traffic to and from a pod.
    - `ns_isolation`: allows incoming traffic only from pods of the same namespace, and all outgoing traffic.
   
   Default: `allow` 

* #####CALICO_IPAM (added in calico-kubernetes v0.2.0)
   Toggles Calico IP Address Management (IPAM). When set to `true`, Calico will automatically assign pods an IP address that is unique in the cluster. When `false`, pods utilize the IP address assigned by Docker.

   Default: `true`  (version >= v0.5.0)

* ##### KUBE_AUTH_TOKEN (added in calico-kubernetes v0.3.0)
   Specifies the token to use for https authentication with the Kubernetes apiserver. Each Kubernetes Service Account has its own API token. You can create Service Accounts by following the instructions in the [Kubernetes docs](http://kubernetes.io/v1.0/docs/user-guide/service-accounts.html).

   Default: None

## Example calico_kubernetes.ini
Below is an example configuration file for the Calico Kubernetes plugin.
```
[config]
ETCD_AUTHORITY=kubernetes-master:6666
KUBE_API_ROOT=https://kubernetes-master:443/api/v1/
DEFAULT_POLICY=ns_isolation
CALICO_IPAM=true
KUBE_AUTH_TOKEN=<INSERT_AUTH_TOKEN>
```
[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/kubernetes/PluginConfiguration.md?pixel)](https://github.com/igrigorik/ga-beacon)
