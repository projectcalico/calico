---
title: Basic policy demo
description: An interactive demo to show how to apply basic network policy to pods in a Calico for Windows cluster.
canonical_url: '/getting-started/windows-calico/demo'
---
This guide provides a simple demo to illustrate basic pod-to-pod connectivity and the application of network policy in a {{site.prodnameWindows}} cluster. We will create client and server pods on Linux and Windows nodes, verify connectivity between the pods, and then we'll apply a basic network policy to isolate pod traffic.

## Prerequisites

To run this demo, you will need a [{{site.prodnameWindows}} cluster]({{site.baseurl}}/getting-started/windows-calico/quickstart) with
Windows Server 1809 (build 17763.1432 August 2020 update or newer). More recent versions of Windows Server can be used with a change to the demo manifests.

>**Note**: Windows Server 1809 (build older than 17763.1432) do not support [direct server return](https://techcommunity.microsoft.com/t5/networking-blog/direct-server-return-dsr-in-a-nutshell/ba-p/693710){:target="_blank"}. This means that policy support is limited to only pod IP addresses.
{: .alert .alert-info}

## Create pods on Linux nodes

First, create a client (busybox) and server (nginx) pod on the Linux nodes:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Namespace
metadata:
  name: calico-demo

---

apiVersion: v1
kind: Pod
metadata:
  labels:
    app: busybox
  name: busybox
  namespace: calico-demo
spec:
  containers:
  - args:
    - /bin/sh
    - -c
    - sleep 360000
    image: busybox:1.28
    imagePullPolicy: Always
    name: busybox
  nodeSelector:
    beta.kubernetes.io/os: linux

---

apiVersion: v1
kind: Pod
metadata:
  labels:
    app: nginx
  name: nginx
  namespace: calico-demo
spec:
  containers:
  - name: nginx
    image: nginx:1.8
    ports:
    - containerPort: 80
  nodeSelector:
    beta.kubernetes.io/os: linux
EOF
```

## Create pods on Window nodes

Next, we'll create a client (powershell) and server (porter) pod on the Windows nodes. First the create the powershell pod.

>**Note**: The powershell and porter pod manifests below use images based on `mcr.microsoft.com/windows/servercore:1809`.
If you are using a more recent Windows Server version, update the manifests to use a [servercore image](https://hub.docker.com/_/microsoft-windows-servercore){:target="_blank"}
that matches your Windows Server version.
{: .alert .alert-info}

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: pwsh
  namespace: calico-demo
  labels:
    app: pwsh
spec:
  containers:
  - name: pwsh
    image: mcr.microsoft.com/windows/servercore:1809
    args:
    - powershell.exe
    - -Command
    - "Start-Sleep 360000"
    imagePullPolicy: IfNotPresent
  nodeSelector:
    kubernetes.io/os: windows
EOF
```

Next, we'll create the porter server pod:

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: porter
  namespace: calico-demo
  labels:
    app: porter
spec:
  containers:
  - name: porter
    image: calico/porter:1809
    ports:
    - containerPort: 80
    env:
    - name: SERVE_PORT_80
      value: This is a Calico for Windows demo.
    imagePullPolicy: IfNotPresent
  nodeSelector:
    kubernetes.io/os: windows
EOF
```

## Check connectivity between pods on Linux and Windows nodes

Now that client and server pods are running on both Linux and Windows nodes, let's verify that client pods
on Linux nodes can reach server pods on Windows nodes. First, we will need the porter pod IP:

```bash
kubectl get po porter -n calico-demo -o 'jsonpath={.status.podIP}'
```

Then we can exec into the busybox pod and try reaching the porter pod on port 80:

```bash
kubectl exec -n calico-demo busybox -- nc -vz <porter_ip> 80
```

To combine both of the above steps:

```bash
kubectl exec -n calico-demo busybox -- nc -vz $(kubectl get po porter -n calico-demo -o 'jsonpath={.status.podIP}') 80
```

If the connection from the busybox pod to the porter pod succeeds, we will get output similar to the following:

```
192.168.40.166 (192.168.40.166:80) open
```

Now let's verify that the powershell pod can reach the nginx pod:

```bash
kubectl exec -n calico-demo pwsh -- powershell Invoke-WebRequest -Uri http://$(kubectl get po nginx -n calico-demo -o 'jsonpath={.status.podIP}') -UseBasicParsing -TimeoutSec 5
```

If the connection succeeds, we will get output similar to:

```
StatusCode        : 200
StatusDescription : OK
Content           : <!DOCTYPE html>
                    <html>
                    <head>
                    <title>Welcome to nginx!</title>
                    <style>
                        body {
                            width: 35em;
                            margin: 0 auto;
                            font-family: Tahoma, Verdana, Arial, sans-serif;
                        }
                    </style>
                    <...
...
```

Finally, let's verify that the powershell pod can reach the porter pod:

```bash
kubectl exec -n calico-demo pwsh -- powershell Invoke-WebRequest -Uri http://$(kubectl get po porter -n calico-demo -o 'jsonpath={.status.podIP}') -UseBasicParsing -TimeoutSec 5
```

If that succeeds, we will see something like:

```
StatusCode        : 200
StatusDescription : OK
Content           : This is a Calico for Windows demo.
RawContent        : HTTP/1.1 200 OK
                    Content-Length: 49
                    Content-Type: text/plain; charset=utf-8
                    Date: Fri, 21 Aug 2020 22:45:46 GMT

                    This is a Calico for Windows demo.
Forms             :
Headers           : {[Content-Length, 49], [Content-Type, text/plain;
                    charset=utf-8], [Date, Fri, 21 Aug 2020 22:45:46 GMT]}
Images            : {}
InputFields       : {}
Links             : {}
ParsedHtml        :
RawContentLength  : 49
```

## Apply policy to the Windows client pod

Now let's apply a basic network policy that allows only the busybox pod to reach the porter pod.

```bash
kubectl apply -f - <<EOF
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-busybox
  namespace: calico-demo
spec:
  podSelector:
    matchLabels:
      app: porter
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: busybox
    ports:
    - protocol: TCP
      port: 80
EOF
```

With the policy in place, the busybox pod should still be able to reach the porter pod:

```bash
kubectl exec -n calico-demo busybox -- nc -vz $(kubectl get po porter -n calico-demo -o 'jsonpath={.status.podIP}') 80
```

However, the powershell pod will not able to reach the porter pod:

```bash
kubectl exec -n calico-demo pwsh -- powershell Invoke-WebRequest -Uri http://$(kubectl get po porter -n calico-demo -o 'jsonpath={.status.podIP}') -UseBasicParsing -TimeoutSec 5
```

The request times out with a message like:

```
Invoke-WebRequest : The operation has timed out.
At line:1 char:1
+ Invoke-WebRequest -Uri http://192.168.40.166 -UseBasicParsing -Timeou ...
+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    + CategoryInfo          : InvalidOperation: (System.Net.HttpWebRequest:Htt
   pWebRequest) [Invoke-WebRequest], WebException
    + FullyQualifiedErrorId : WebCmdletWebResponseException,Microsoft.PowerShe
   ll.Commands.InvokeWebRequestCommand

command terminated with exit code 1
```

## Wrap up

In this demo we've brought up pods on Linux and Windows nodes, verified basic pod connectivity, and tried a
basic network policy to isolate pod to pod traffic. Finally, we can clean up all of our demo resources:

```bash
kubectl delete ns calico-demo
```

