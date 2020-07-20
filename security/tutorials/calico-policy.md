---
title: Calico policy tutorial
description: Learn how to create more advanced Calico network policies (namespace, allow and deny all ingress and egress).
canonical_url: "/security/tutorials/calico-policy"
---

Calico network policies **extend** the functionalities of Kubernetes network policies. To demonstrate this, this tutorial follows a similar approach to the [Kubernetes Advanced Network Policy Tutorial]({{ site.baseurl }}/security/tutorials/kubernetes-policy-advanced), and implements it using Calico network policies. It not only highlights the syntactical differences between the two policy types, but also demonstrates the flexibility of Calico network policies.

### Requirements

- A working Kubernetes cluster and access to it using kubectl and calicoctl
- Your Kubernetes nodes have connectivity to the public internet
- You are familiar with [Calico NetworkPolicy]({{ site.baseurl }}/security/calico-network-policy)

### Tutorial flow

1. Create the namespace and NGINX service
2. Configure default deny
3. Allow egress traffic from busybox
4. Allow ingress traffic to NGINX
5. Clean up

### 1. Create the namespace and nginx service

We'll use a new namespace for this guide. Run the following commands to create the namespace and a plain NGINX service listening on port 80.

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

We will begin by using a default deny [Global Calico Network Policy]({{ site.baseurl }}/reference/resources/globalnetworkpolicy) (which you can only do using Calico) that will help us adopt best practices in using a [zero trust network model]({{ site.baseurl }}/security/adopt-zero-trust) to secure our workloads. Note that Global Calico Network Policies don't need a namespace, this will effect all resources that match the selector (which in our case is anything that doesn't match the kube-system namespace). Kubernetes Network Policies cannot achieve this by themselves. Note here that we are allowing important kube-system pods to still have wide permissions so that these pods can perform important tasks relevant to the kubernetes cluster.

```bash
calicoctl create -f - <<EOF
apiVersion: projectcalico.org/v3
kind: GlobalNetworkPolicy
metadata:
  name: default-deny
spec:
  selector: projectcalico.org/namespace != "kube-system"
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

### 3. Allow egress traffic from busybox

Let's create a Calico Network Policy which allows egress traffic from the busybox "access" pod.

```bash
calicoctl create -f - <<EOF
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-busybox-egress
  namespace: advanced-policy-demo
spec:
  selector: run == 'access'
  types:
  - Egress
  egress:
  - action: Allow
EOF
```

#### Verify egress - allowed traffic from "access" pod to google but not nginx

Now run the command to verify that we can access the nginx service.

```bash
wget -q --timeout=5 nginx -O -
```

It will return:

```
wget: download timed out
```

{: .no-select-button}

Next, try to retrieve the home page of google.com.

```bash
wget -q --timeout=5 google.com -O -
```

It will return the HTML of the google home page.

{: .no-select-button}

Access to google is allowed because we have allowed all egress traffic from the busybox pod, however we still cannot access the nginx service because we have not allowed ingress traffic into that service. Let's do that now.

### 4. Allow ingress traffic to nginx

Let's create a Calico Network Policy that allows ingress traffic into the nginx service from the busybox.

```bash
calicoctl create -f - <<EOF
apiVersion: projectcalico.org/v3
kind: NetworkPolicy
metadata:
  name: allow-nginx-ingress
  namespace: advanced-policy-demo
spec:
  selector: app == 'nginx'
  types:
  - Ingress
  ingress:
  - action: Allow
    source:
      selector: run == 'access'
EOF
```

#### Verify access - allowed ingress traffic to nginx from "access" pod

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

It will return the HTML of the google home page.

{: .no-select-button}

We have allowed our access pod access to the outside internet and the nginx service using Calico Network Policies!

## 5. Clean up namespace

Delete the advanced policy demo namespace to clean up this tutorial session and run the following commands to clear the Calico Network Policies.

```bash
calicoctl delete policy allow-busybox-egress -n advanced-policy-demo
calicoctl delete policy allow-busybox-egress -n advanced-policy-demo
calicoctl delete gnp default-deny
kubectl delete ns advanced-policy-demo
```
