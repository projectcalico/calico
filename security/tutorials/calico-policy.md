---
title: Calico policy tutorial
description: Learn how to create more advanced Calico network policies (namespace, allow and deny all ingress and egress).
canonical_url: "/security/tutorials/calico-policy"
---

Calico network policies **extend** the functionalities of Kubernetes network policies. To demonstrate this, this tutorial takes the Kubernetes Advanced NetworkPolicy tutorial, and implements it using Calico network policies. It not only highlights the syntactical differences between the two policy types, but also demonstrates the flexibility of Calico network policies.

### Requirements

- Calico v2.6.1+ with Kubernetes 1.8+
- calicoctl and kubectl
- A working Kubernetes cluster and access to it using kubectl and calicoctl

### Tutorial flow

1. Create the Namespace, Nginx Service and Busybox
1. Deny all Ingress traffic
1. Allow Ingress traffic to Nginx
1. Deny all Egress traffic
1. Allow Egress traffic to kube-dns
1. Clean up Namespace

### 1. Create the namespace and nginx service

We'll use a new namespace for this guide. Run the following commands to create the namespace and a plain nginx service listening on port 80.

```bash
kubectl create ns advanced-policy-demo
kubectl create deployment --namespace=advanced-policy-demo nginx --image=nginx
kubectl expose --namespace=advanced-policy-demo deployment nginx --port=80
```

#### Verify access - allowed all ingress and egress

Open up a second shell session which has `kubectl` connectivity to the Kubernetes cluster and create a busybox pod to test policy access. This pod will be used throughout this tutorial to test policy access.

```bash
kubectl run --namespace=advanced-policy-demo access --rm -ti --image busybox /bin/sh
```

This will open up a shell session inside the `busybox` pod, as shown below.

```
Waiting for pod advanced-policy-demo/access-472357175-y0m47 to be running, status is Pending, pod ready: false

If you don't see a command prompt, try pressing enter.
/ #
```

{: .no-select-button}

Now from within the busybox "access" pod execute the following command to test access to the nginx service.

```bash
wget -q --timeout=5 nginx -O -
```

It returns the HTML of the nginx welcome page.

Still within the busybox "access" pod, issue the following command to test access to google.com.

```bash
wget -q --timeout=5 google.com -O -
```

It returns the HTML of the google.com home page.

### 2. Lock down all traffic

We will begin by using a default deny [Global Calico Network Policy](https://docs.projectcalico.org/reference/resources/globalnetworkpolicy) (which you can only do using Calico) that will help us adopt best practices in using a [zero trust network model](https://docs.projectcalico.org/security/adopt-zero-trust) to secure our workloads. Note that Global Calico Network Policies don't need a namespace, this will effect all resources that match the selector. Kubernetes Network Policies cannot achieve this by themselves.

```bash
calicoctl create -f - <<EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-deny
spec:
  selector: all()
  types:
  - Ingress
  - Egress
EOF
```

#### Verify access - denied all ingress and egress

Because all pods in the namespace are now selected, any ingress traffic which is not explicitly allowed by a policy will be denied.

We can see that this is the case by switching over to our "access" pod in the namespace and attempting to access the nginx service.

```bash
wget -q --timeout=5 nginx -O -
```

It will return:

```
wget: bad address 'google.com'
```

{: .no-select-button}

Next, try to access google.com.

```bash
wget -q --timeout=5 google.com -O -
```

It will return:

```
wget: bad address 'google.com'
```

{: .no-select-button}

Now that we have the defalt deny Global Calico Network Policy, all ingress / egress traffic is denied _everywhere_.

### 3. Allow kube-system pods to communicate

Kubernetes uses the kube-system namespace to create pods for the kubernetes cluster to function properly. Let's give this namespace wide permissions to allow these specific pods to function normally. It's important to note here that specific Calico Network Policies are namespaced resources that applies to workloads in that namespace whereas the Calico Global Network Policy is a non-namespaced resource and can be applied to any kind of endpoint (pods, VMs, host interfaces) independent of namespace.

```bash
calicoctl create -f - <<EOF
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-kube-system
  namespace: kube-system
spec:
  selector: all()
  types:
  - Ingress
  - Egress
  ingress:
  - action: Allow
  egress:
  - action: Allow
EOF
```

### 4. Allow traffic to Nginx from Busybox

Create another Calico Network Policy which allows traffic from the nginx pod from the busybox "access" pod.

```bash
calicoctl create -f - <<EOF
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-busybox-nginx
  namespace: advanced-policy-demo
spec:
  selector: all()
  types:
  - Ingress
  - Egress
  ingress:
  - action: Allow
    source:
      selector: run == 'access'
    destination:
      selector: app == 'nginx'
  egress:
  - action: Allow
EOF
```

#### Verify access - allowed traffic to nginx from "access" pod

Now run the command to verify that we can access the nginx service.

```bash
wget -q --timeout=5 nginx -O -
```

It will return the HTML of the nginx welcome page.

```
<!DOCTYPE html>
<html>
<head>
<title>Welcome to nginx!</title>...
```

{: .no-select-button}

Next, try to retrieve the home page of google.com.

```bash
wget -q --timeout=5 google.com -O -
```

It returns:

```
wget: download timed out
```

{: .no-select-button}

Access to `google.com` times out because we have not allowed that in our network policy the default deny still applies here, only the traffic that we have specified through policies are allowed through.

## 7. Clean up namespace

Delete the advanced policy demo namespace to clean up this tutorial session.

```bash
kubectl delete ns advanced-policy-demo
```
