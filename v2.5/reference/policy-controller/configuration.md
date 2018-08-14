---
title: Configuring the Calico policy controller
canonical_url: 'https://docs.projectcalico.org/v3.2/reference/kube-controllers/configuration'
---

The policy controller is primarily configured through environment variables.  When running
the policy controller as a Kubernetes pod, this is accomplished through the pod manifest `env`
section.

## The calico/kube-policy-controller container

### Configuring etcd access 

The policy controller supports the following environment variables to configure 
etcd access:

* `ETCD_ENDPOINTS`: The list of etcd nodes in your cluster. e.g `http://10.0.0.1:2379,http://10.0.0.2:2379`
* `ETCD_CA_CERT_FILE`: The full path to the CA certificate file for the Certificate Authority that signed the etcd server key/certificate pair.
* `ETCD_CERT_FILE`: The full path to the client certificate file for accessing the etcd cluster.
* `ETCD_KEY_FILE`: The full path to the client key file for accessing the etcd cluster.

> NOTE: When running etcd with TLS enabled, the addresses in ETCD_ENDPOINTS must be hostname values, NOT an IP address, such as etcd-host:2379.

The `*_FILE` variables are _paths_ to the corresponding certificates / keys.  As such, when the policy controller is running as a Kubernetes pod, you
must ensure that the files exist within the pod.  This is usually done in one of two ways:

* Mount the certificates from the host.  This requires that the certs be present on the host that the policy controller is scheduled to / running on.
* Use Kubernetes [Secrets](http://kubernetes.io/docs/user-guide/secrets/) to mount the certificates into the Pod as files.

### Configuring Kubernetes API access

The policy controller must access the Kubernetes API in order to learn about NetworkPolicy, Pod, and Namespace events.

The following environment variables are useful for configuring API access:

* `K8S_API`: The location of the Kubernetes API, including transport and port. e.g `https://kubernetes.default:443`
* `CONFIGURE_ETC_HOSTS`: Whether or not the policy controller should configure its /etc/hosts file to resolve the Kubernetes Service clusterIP.  When "true", the policy controller will resolve `kubernetes.default` to the configured clusterIP of the Kubernetes API.

It is recommended to use the following configuration for API access:

```
- name: K8S_API
  value: "https://kubernetes.default:443"
- name: CONFIGURE_ETC_HOSTS
  value: "true"
```

## The leader election container

The leader election container is an optional sidecar container which performs leader election using the Kubernetes API.
This ensures that only a single instance of the policy controller is ever active.  

The leader election container is only recommended when running the policy controller as a static pod in a multi-master deployment. 

However, it is instead recommended to use a `ReplicaSet` with a single replica to ensure that one instance
will always be running without need for leader election.

### Kubernetes API access

The leader election container also needs Kubernetes API access, which can be configured through a `kubeconfig` file placed in 
the root directory of the container. This can be done by mounting a file from the host, or using Kubernetes [ConfigMap resources](https://kubernetes.io/docs/tasks/configure-pod-container/configure-pod-configmap/).

### Other configuration

* `LOG_LEVEL`: Supports the standard Python log levels. e.g. `LOG_LEVEL=debug`, defaults to `info`

More information on leader election can be found in the [kubernetes/contrib](https://github.com/kubernetes/contrib/tree/master/election#simple-leader-election-with-kubernetes-and-docker) repository.
