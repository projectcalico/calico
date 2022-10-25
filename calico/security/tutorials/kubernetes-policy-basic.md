---
title: Kubernetes policy, basic tutorial
description: Learn how to use basic Kubernetes network policy to securely restrict traffic to/from pods. 
canonical_url: '/security/tutorials/kubernetes-policy-basic'
---

This guide provides a simple way to try out Kubernetes `NetworkPolicy` with {{site.prodname}}.  It requires a Kubernetes cluster configured with {{site.prodname}} networking, and expects that you have `kubectl` configured to interact with the cluster.

You can quickly and easily deploy such a cluster by following one of the [installation guides]({{ site.baseurl }}/getting-started/kubernetes/).

### Configure namespaces

This guide will deploy pods in a Kubernetes namespace.  Let's create the `Namespace` object for this guide.

```bash
kubectl create ns policy-demo
```

### Create demo pods

We'll use Kubernetes `Deployment` objects to easily create pods in the namespace.

1. Create some nginx pods in the `policy-demo` namespace.

   ```bash
   kubectl create deployment --namespace=policy-demo nginx --image=nginx
   ```

1. Expose them through a service.

   ```bash
   kubectl expose --namespace=policy-demo deployment nginx --port=80
   ```

1. Ensure the nginx service is accessible.

   ```bash
   kubectl run --namespace=policy-demo access --rm -ti --image busybox /bin/sh
   ```

   This should open up a shell session inside the `access` pod, as shown below.

   ```
   Waiting for pod policy-demo/access-472357175-y0m47 to be running, status is Pending, pod ready: false

   If you don't see a command prompt, try pressing enter.

   / #
   ```
   {: .no-select-button}

1. From inside the `access` pod, attempt to reach the `nginx` service.

   ```bash
   wget -q nginx -O -
   ```

   You should see a response from `nginx`.  Great! Our service is accessible.  You can exit the pod now.

### Enable isolation

Let's turn on isolation in our `policy-demo` namespace.  {{site.prodname}} will then prevent connections to pods in this namespace.

Running the following command creates a NetworkPolicy which implements a default deny behavior for all pods in the `policy-demo` namespace.

```bash
kubectl create -f - <<EOF
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: default-deny
  namespace: policy-demo
spec:
  podSelector:
    matchLabels: {}
EOF
```

#### Test Isolation

This will prevent all access to the nginx service.  We can see the effect by trying to access the service again.

```bash
kubectl run --namespace=policy-demo access --rm -ti --image busybox /bin/sh
```

This should open up a shell session inside the `access` pod, as shown below.

```
Waiting for pod policy-demo/access-472357175-y0m47 to be running, status is Pending, pod ready: false

If you don't see a command prompt, try pressing enter.

/ #
```
{: .no-select-button}

Now from within the busybox `access` pod execute the following command to test access to the nginx service.

```bash
wget -q --timeout=5 nginx -O -
```

The request should time out after 5 seconds.

```
wget: download timed out
/ #
```
{: .no-select-button}

By enabling isolation on the namespace, we've prevented access to the service.

### Allow access using a network policy

Now, let's enable access to the nginx service using a NetworkPolicy.  This will allow incoming connections from our `access` pod, but not
from anywhere else.

Create a network policy `access-nginx` with the following contents:

```bash
kubectl create -f - <<EOF
kind: NetworkPolicy
apiVersion: networking.k8s.io/v1
metadata:
  name: access-nginx
  namespace: policy-demo
spec:
  podSelector:
    matchLabels:
      app: nginx
  ingress:
    - from:
      - podSelector:
          matchLabels:
            run: access
EOF
```

> **Note**: The NetworkPolicy allows traffic from Pods with
> the label `run: access` to Pods with the label `app: nginx`. The
> labels are automatically added by kubectl and
> are based on the name of the resource.
{: .alert .alert-info}

We should now be able to access the service from the `access` pod.

```bash
kubectl run --namespace=policy-demo access --rm -ti --image busybox /bin/sh
```

This should open up a shell session inside the `access` pod, as shown below.

```
Waiting for pod policy-demo/access-472357175-y0m47 to be running, status is Pending, pod ready: false

If you don't see a command prompt, try pressing enter.

/ #
```
{: .no-select-button}

Now from within the busybox `access` pod execute the following command to test access to the nginx service.

```bash
wget -q --timeout=5 nginx -O -
```

However, we still cannot access the service from a pod without the label `run: access`.
We can verify this as follows.

```bash
kubectl run --namespace=policy-demo cant-access --rm -ti --image busybox /bin/sh
```

This should open up a shell session inside the `cant-access` pod, as shown below.

```
Waiting for pod policy-demo/cant-access-472357175-y0m47 to be running, status is Pending, pod ready: false

If you don't see a command prompt, try pressing enter.

/ #
```
{: .no-select-button}

Now from within the busybox `cant-access` pod execute the following command to test access to the nginx service.

```bash
wget -q --timeout=5 nginx -O -
```

The request should time out.

```
wget: download timed out
/ #
```
{: .no-select-button}

You can clean up the demo by deleting the demo namespace.

```bash
kubectl delete ns policy-demo
```

This was just a simple example of the Kubernetes NetworkPolicy API and how Calico can secure your Kubernetes cluster.  For more
information on network policy in Kubernetes, see the [Kubernetes user-guide](http://kubernetes.io/docs/user-guide/networkpolicies/){:target="_blank"}.

For a slightly more detailed demonstration of policy, check out the [Kubernetes policy demo](kubernetes-policy-demo/kubernetes-demo).
