## Enabling NetworkPolicy objects in Kubernetes 

To enable the Kubernetes API extensions, you first need to make sure your apiserver is started with the following option:
```
--runtime-config=extensions/v1beta1=true,extensions/v1beta1/thirdpartyresources=true
```

Then, you can enable the `NetworkPolicy` third- party resource in the API.  Create the `NetworkPolicy` resource manifest from this repo.
```
kubectl create --validate=false -f https://raw.githubusercontent.com/caseydavenport/k8s-policy-agent/master/examples/NetworkPolicy.yaml 
```

## Enabling NetworkPolicy support in Calico
To allow Calico to render NetworkPolicy you must start the Calico policy agent.  The policy agent runs as a pod on Kubernetes.  It reads from the Kubernetes API and configures Calico with the correct network policies.
```
# Get the manifest.
wget https://raw.githubusercontent.com/caseydavenport/k8s-policy-agent/master/examples/calico-policy-rc.yaml

# Create the replication controller.
kubectl create -f calico-policy-rc.yaml 
```
> You must edit the manifest to include the ETCD_AUTHORITY and API token (if applicable). 

In order to program NetworkPolicy objects, you need to run a specific version of the `calico/node` container on each of your hosts.
```
calicoctl node --node-image=caseydavenport/node:policy
```
> Make sure you are using calicoctl version v0.16.0 or later.

You must also use a specific version of the Calico CNI plugin on each node.
```
wget -O /opt/cni/bin/calico https://github.com/caseydavenport/calico-cni/releases/download/Policy/calico 
```

And you must specify policy type "none" in your CNI network config file.
```
core@calico-02 ~ $ cat /etc/cni/net.d/10-calico.conf
{
    "name": "calico-k8s-network",
    "type": "calico",
    "etcd_authority": "localhost:2379",
    "log_level": "info",
    "ipam": {
        "type": "calico-ipam"
    },
    "policy": {
        "type": "none"
    }
}
```

## Enabling per-namespace isolation
You can enable isolation on a per-namespace basis.  Enabling isolation will prevent all incoming traffic to all pods within that namespace, unless otherwise allowed by a `NetworkPolicy` object.

To enable isolation on a namespace:
```
kubectl annotate ns <namespace> "net.alpha.kubernetes.io/network-isolation=yes" --overwrite=true
```

To disable isolation on a namespace:
```
kubectl annotate ns <namespace> "net.alpha.kubernetes.io/network-isolation=no" --overwrite=true
```

## Creating NetworkPolicy objects
NetworkPolicy objects support the following schema.

```
kind: NetworkPolicy
apiVersion: net.alpha.kubernetes.io/v1alpha1
metadata:
  name: POLICY_NAME
  namespace: default 
spec:
  podSelector:         // Standard label selector - selects pods.
  ingress:             // (Optional) List of allow rules.
    ports:             // (Optional) List of dest ports to open.
    - port:            // (Optional) Numeric or named port 
      protocol:        // [ TCP | UDP]
    from:              // (Optional) List of sources.
     - pods:           // (Optional) Standard label selector.
       namespaces:     // (Optional) Standard label selector.
```
You can POST them (as json) to: `<master>/apis/net.alpha.kubernetes.io/v1alpha1/namespaces/<namespace>/networkpolicys`
You can GET them from: `<master>/apis/net.alpha.kubernetes.io/v1alpha1/networkpolicys`


This repository comes with a tool named `policy` which can be used to manage policies.  
```
wget https://github.com/caseydavenport/k8s-policy-agent/releases/download/v0.1.0/policy
```

It is configurable via environment variables. 
```
export KUBE_API_ROOT=http://localhost:8080
export KUBE_AUTH_TOKEN="<auth_token>"
```
> You can find your auth token using `kubectl describe secret`

Examples:
```
cat policy.yaml | policy create
```

```
policy delete default my-policy 
```

```
policy list
```

```
policy get default my-policy
```
