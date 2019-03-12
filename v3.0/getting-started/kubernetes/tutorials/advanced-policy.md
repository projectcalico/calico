---
title: Controlling ingress and egress traffic with network policy
canonical_url: https://docs.projectcalico.org/v3.6/getting-started/kubernetes/tutorials/advanced-policy
---

The Kubernetes `NetworkPolicy` API allows users to express ingress and egress policies (starting with Kubernetes 1.8.0) to Kubernetes pods
based on labels and ports.

This guide walks through using Kubernetes `NetworkPolicy` to define more complex network policies.

### Requirements

- This guide is aimed at Calico v2.6.1+ on top of Kubernetes 1.8+, and will not work on previous versions of Calico or Kubernetes
- This guide assumes you have a working Kubernetes cluster and access to it using kubectl.
- This guide assumes that your Kubernetes nodes have connectivity to the public internet.
- This guide assumes you are familiar with [Kubernetes NetworkPolicy](simple-policy)

### Tutorial Flow

1. Create the Namespace and Nginx Service
1. Deny all ingress traffic
1. Allow ingress traffic to Nginx
1. Deny all egress traffic
1. Allow egress traffic to kube-dns
1. Cleanup Namespace

### 1. Create the Namespace and Nginx Service

We'll use a new namespace for this guide.  Run the following commands to create it and a plain nginx service listening on port 80.

```shell
kubectl create ns advanced-policy-demo
kubectl run --namespace=advanced-policy-demo nginx --replicas=2 --image=nginx
kubectl expose --namespace=advanced-policy-demo deployment nginx --port=80
```

#### Verify Access - Allowed All Ingress and Egress

Open up a second shell session which has `kubectl` connectivity to the Kubernetes cluster and create a busybox pod to test policy access.  This pod will be used throughout this tutorial to test policy access.

```shell
$ kubectl run --namespace=advanced-policy-demo access --rm -ti --image busybox /bin/sh

Waiting for pod advanced-policy-demo/access-472357175-y0m47 to be running, status is Pending, pod ready: false

If you don't see a command prompt, try pressing enter.
/ #
```

Now from within the busybox "access" pod execute the following commands to test access.

```shell
/ # wget -q --timeout=5 nginx -O -
/ # wget -q --timeout=5 google.com -O -
```

Both of the commands should respond with raw HTML response data from the nginx and google.com website.

### 2. Deny all ingress traffic

Enable ingress isolation on the namespace by deploying a [default deny all ingress traffic policy](https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-deny-all-ingress-traffic).

```shell
kubectl create -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: advanced-policy-demo
spec:
  podSelector:
    matchLabels: {}
  policyTypes:
  - Ingress
EOF
```

#### Verify Access - Denied All Ingress and Allowed All Egress

Because all pods in the namespace are now selected, any ingress traffic which is not explicitly allowed by a policy will be denied.

We can see that this is the case by switching over to our "access" pod in the namespace and attempting to access the nginx Service.

```shell
/ # wget -q --timeout=5 nginx -O -
wget: download timed out
/ # wget -q --timeout=5 google.com -O -
<!doctype html><html itemscope="" item....
```

We can see that the ingress access to the nginx service is denied while egress access to outbound internet is still allowed.

### 3. Allow ingress traffic to Nginx

Run the following to create a `NetworkPolicy` which allows traffic to nginx pods from any pods in the `advanced-policy-demo` namespace.

```shell
kubectl create -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: access-nginx
  namespace: advanced-policy-demo
spec:
  podSelector:
    matchLabels:
      run: nginx
  ingress:
    - from:
      - podSelector:
          matchLabels: {}
EOF
```

#### Verify Access - Allowed Nginx Ingress

Now ingress traffic to nginx will be allowed.  We can see that this is the case by switching over to our "access" pod in the namespace and attempting to access the nginx service.

```shell
/ # wget -q --timeout=5 nginx -O -
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>...
```

After creating the policy, we can now access the nginx Service.

### 4. Deny all egress traffic

Enable egress isolation on the namespace by deploying a [default deny all egress traffic policy](https://kubernetes.io/docs/concepts/services-networking/network-policies/#4-deny-all-egress-traffic).

```shell
kubectl create -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: advanced-policy-demo
spec:
  podSelector:
    matchLabels: {}
  policyTypes:
  - Egress
EOF
```

#### Verify Access - Denied All Egress

Now any ingress or egress traffic which is not explicitly allowed by a policy will be denied.

We can see that this is the case by switching over to our "access" pod in the
namespace and attempting to `nslookup` nginx or `wget` google.com.

```shell
/ # nslookup nginx
Server:    10.96.0.10
Address 1: 10.96.0.10


nslookup: can't resolve 'nginx'
/ # wget -q --timeout=5 google.com -O -
wget: bad address 'google.com'
```

> **Note**: The `nslookup` command can take a minute or more to timeout.
{: .alert .alert-info}

### 5. Allow DNS egress traffic

Run the following to create a label of `name: kube-system` on the `kube-system` namespace and a `NetworkPolicy` which allows DNS egress traffic
from any pods in the `advanced-policy-demo` namespace to the `kube-system` namespace.

```shell
kubectl label namespace kube-system name=kube-system
kubectl create -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-access
  namespace: advanced-policy-demo
spec:
  podSelector:
    matchLabels: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          name: kube-system
    ports:
    - protocol: UDP
      port: 53

EOF
```

#### Verify Access - Allowed DNS access

Now egress traffic to DNS will be allowed.

We can see that this is the case by switching over to our "access" pod in the namespace and attempting to lookup nginx and google.com.

```shell
/ # nslookup nginx
Server:    10.0.0.10
Address 1: 10.0.0.10 kube-dns.kube-system.svc.cluster.local
/ # nslookup google.com
Name:      google.com
Address 1: 2607:f8b0:4005:807::200e sfo07s16-in-x0e.1e100.net
Address 2: 216.58.195.78 sfo07s16-in-f14.1e100.net
```

Even though DNS egress traffic is now working, all other egress traffic from all pods in the advanced-policy-demo namespace is still blocked.  Therefore the HTTP egress traffic from the `wget` calls will still fail.

### 6. Allow egress traffic to nginx

Run the following to create a `NetworkPolicy` which allows egress traffic from any pods in the `advanced-policy-demo` namespace to pods with labels matching `run: nginx` in the same namespace.

```shell
kubectl create -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-egress-to-advance-policy-ns
  namespace: advanced-policy-demo
spec:
  podSelector:
    matchLabels: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - podSelector:
        matchLabels:
          run: nginx
EOF
```

#### Verify Access - Allowed Egress access to nginx

We can see that this is the case by switching over to our "access" pod in the
namespace and attempting to access `nginx`.

```shell
/ # wget -q --timeout=5 nginx -O -
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>...
/ # wget -q --timeout=5 google.com -O -
wget: download timed out
```

Access to `google.com` times out because it can resolve DNS but has no egress access to anything other than pods with labels matching `run: nginx` in the `advanced-policy-demo` namespace.

## 7. Cleanup Namespace

You can clean up after this tutorial by deleting the advanced policy demo namespace.

```shell
kubectl delete ns advanced-policy-demo
```
