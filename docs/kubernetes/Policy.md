<!--- master only -->
> ![warning](../images/warning.png) This document applies to the HEAD of the calico-docker source tree.
>
> View the calico-docker documentation for the latest release [here](https://github.com/projectcalico/calico-docker/blob/v0.13.0/README.md).
<!--- else
> You are viewing the calico-docker documentation for release **release**.
<!--- end of master only -->

# Calico Policy for Kubernetes
The Calico CNI plugin for Kubernetes allows you to specify network policy in the Kubernetes API using annotations.  
> *Note*: annotation-based policy is currently experimental and is subject to change in future releases. 

## Prerequisites
* A Kubernetes v1.1 Deployment using the Calico CNI plugin.
* You must be using the iptables kube-proxy in your deployment. This is the default proxy mode in Kubernetes v1.1.3.

## Behavior
Without annotation-based policy enabled, Calico follows the [Kubernetes networking model][k8s-network-model], allowing full connectivity between pods.

When Calico's annotation-based policy is enabled: 
- Pods will be, by default, isolated by namespace boundaries. Only pods in the same namespace can communicate.
- Annotations can be used to expose access to pods outside of their namespace. 
- Annotations can be used to futher isolate pods within their namespace.
- Pods in the `kube-system` namespace (such as SkyDNS), are accessible to the rest of the cluster.  

Since pods are, by default, isolated by namespace boundaries, they will:
- not be accessible by pods outside of their namespace unless explicitly allowed via annoations.  
- not be accessible via Kubernetes service IPs, NodePort services, or LoadBalancer services unless specificaly allowed using an annotation.
- not be accessible by the compute hosts in your cluster unless specificaly allowed using an annotation. 

## Enabling annotation-based policy
To enable annotation-based policy, add the `policy` section to your CNI network config file as shown.
```
$ cat /etc/cni/net.d/10-calico.conf
{
    "name": "calico-k8s-network",
    "type": "calico",
    "etcd_authority": "<ETCD_IP:ETCD_PORT>",
    "log_level": "info",
    "ipam": {
        "type": "calico-ipam"
    },
    "policy": {
        "type": "k8s-annotations",
        "k8s_api_root": "<KUBERNETES_API_ROOT>",
        "k8s_auth_token": "<AUTH_TOKEN>"
    }
}
```

The following configuration optons are supported in the `policy` section:
- `type`: The type of policy to use.  Currently, only `k8s-annotations` is supported.
- `k8s_api_root`: (Optional) Location of the Kubernetes API.  Default: `https://10.100.0.1:443/api/v1/`
- `k8s_auth_token`: (Optional) ServiceAccount token for accessing a secure API.  Default: `None`

Once you have modified the network configuration file, you will need to restart the kubelet to pick up the changes.

## Declaring Policy using Annotations
With `k8s-annotations` policy enabled, you can now declare network policy on pods at creation time using annotations.  Annotations allow you to contol network access to pods using the Calico distributed firewall. 

The following describes the supported syntaxes for declaring a single annotation-based rule.  Multiple rules can be defined using a semicolon.
```
allow
allow from [label <KEY>=<VAL>] [cidr <CIDR>]
allow (tcp|udp) [from [ports <PORTS>] [label <KEY>=<VAL>] [cidr <CIDR>]]
allow icmp [type <ICMPTYPE [code <ICMPCODE>]] [from [label <KEY>=<VAL>] [cidr <CIDR>]]
```

## Examples

### Example 1: Exposing outside of a namespace.
When `k8s-annotations` policy is enabled, Calico will reject incoming connections to pods from outside of their
namespace. 

The RecplicationController manifest in this example shows how to use annotations to expose pods outside of their namespace. 

This allows:
- incoming connections from pods in other namespaces.
- incoming connections from NodePort and LoadBalancer services (external connectivity). 
- incoming connections from compute hosts in your cluster.

to tcp and udp port 80 on the destination pods.

```
apiVersion: v1
kind: ReplicationController
metadata:
  name: frontend
spec:
  replicas: 3
  template:
    metadata:
      annotations:
        projectcalico.org/policy: "allow tcp to port 80; allow udp to port 80"
      labels:
        tier: frontend
    spec:
      containers:
      - name: php-redis
        image: gcr.io/google_samples/gb-frontend:v3
        ports:
        - containerPort: 80
```

### Example 2: Policy using labels
This example shows how to limit incoming connections to a subset of pods using labels.  The pods created by this
ReplicationController will accept all traffic from source pods in the same namespace with the label `tier=frontend`.  All other traffic will
be dropped.
```
apiVersion: v1
kind: ReplicationController
metadata:
  name: frontend
spec:
  replicas: 3
  template:
    metadata:
      annotations:
        projectcalico.org/policy: "allow from label tier=frontend"
      labels:
        tier: frontend
    spec:
      containers:
      - name: php-redis
        image: gcr.io/google_samples/gb-frontend:v3
        ports:
        - containerPort: 80
```


[k8s-network-model]: https://github.com/kubernetes/kubernetes/blob/master/docs/design/networking.md#networking

[![Analytics](https://ga-beacon.appspot.com/UA-52125893-3/calico-docker/docs/kubernetes/KubernetesPolicy.md?pixel)](https://github.com/igrigorik/ga-beacon)
