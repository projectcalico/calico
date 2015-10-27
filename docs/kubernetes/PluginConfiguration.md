# Configuring the Calico Kubernetes Plugin

The Calico network plugin is configurable via environment variables. Each variable assumes a default value, but can be overridden in the environment for the `kubelet` process.

* #####ETCD_AUTHORITY (added in calico-kubernetes v0.1.0)
   The location of the Calico `etcd` datastore in the form `<IP>:<PORT>`.
   
   Default: `kubernetes-master:6666`.

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

   Default: `false` (version < v0.5.0)

* ##### KUBE_AUTH_TOKEN (added in calico-kubernetes v0.3.0)
   Specifies the token to use for https authentication with the Kubernetes apiserver. Each Kubernetes Service Account has its own API token. You can create Service Accounts by following the instructions in the [Kubernetes docs](http://kubernetes.io/v1.0/docs/user-guide/service-accounts.html).

   Default: None

+ #####CALICOCTL_PATH (Deprecated)
   _Deprecated in [calico-kubernetes v0.4.0](https://github.com/projectcalico/calico-kubernetes/releases/tag/v0.4.0)_

   Path to the `calicoctl` binary.

   Default: `calicoctl`

