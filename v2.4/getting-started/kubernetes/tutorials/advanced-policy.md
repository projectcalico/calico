---
title: Going Beyond `NetworkPolicy` with Calico
canonical_url: 'https://docs.projectcalico.org/v3.5/getting-started/kubernetes/tutorials/advanced-policy'
---

The Kubernetes NetworkPolicy API allows users to express ingress policy to Kubernetes pods
based on labels and ports.  Calico implements this API, but also supports a number of
policy features which are not currently expressble through the NetworkPolicy API such as CIDR
and egress policy.

This guide walks through using the Calico APIs directly in conjunction with Kubernetes NetworkPolicy
in order to define more complex network policies.

### Requirements

- This guide is aimed at Calico v2.4 and above, and will not work on Calico v2.3 or below.
- This guide assumes you have a working Kubernetes cluster with Calico for policy. (See: [installation]({{site.baseurl}}/{{page.version}}/getting-started/kubernetes/installation) for help)
- This guide assumes that your pods have connectivity to the public internet.
- This guide assumes you are familiar with [Kubernetes NetworkPolicy](simple-policy)
- This guide assumes you are using etcdv2 (or v3) as the Calico backend datastore.
- You must have configured kubectl access to the cluster.
- You must have installed and [configured the calicoctl tool]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/etcdv2)

### Setup

#### Create the Namespace

We'll use a new namespace for this guide.  Run the following command to create it.

```
kubectl create ns advanced-policy-demo
```

And then enable isolation on the Namespace using a [default policy](https://kubernetes.io/docs/concepts/services-networking/network-policies/#default-policies).

```
kubectl create -f - <<EOF
kind: NetworkPolicy
apiVersion: extensions/v1beta1
metadata:
  name: default-deny
  namespace: advanced-policy-demo
spec:
  podSelector:
EOF
```

#### Run an nginx Service

We'll run an nginx Service in the Namespace.

```shell
kubectl run --namespace=advanced-policy-demo nginx --replicas=2 --image=nginx
kubectl expose --namespace=advanced-policy-demo deployment nginx --port=80
```

#### Check using calicoctl

  > **Note:**
  >
  > This requires the [calicoctl tool to be configured]({{site.baseurl}}/{{page.version}}/reference/calicoctl/setup/etcdv2).
  > For example: `export ETCD_ENDPOINTS=http://10.96.232.136:6666`

Now that we've created a Namespace and a set of pods, we should see those objects show up in the
Calico API using `calicoctl`.

We can see that the Namespace has a corresponding [Profile]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/profile).

```shell
$ calicoctl get profile -o wide
NAME                          TAGS
k8s_ns.advanced-policy-demo   k8s_ns.advanced-policy-demo
k8s_ns.default                k8s_ns.default
k8s_ns.kube-public            k8s_ns.kube-public
k8s_ns.kube-system            k8s_ns.kube-system
```

Because all pods in the namespace are now selected, any traffic which is not explicitly allowed by a policy will be denied.

We can see that this is the case by running another pod in the Namespace and attempting to
access the nginx Service.

```
$ kubectl run --namespace=advanced-policy-demo access --rm -ti --image busybox /bin/sh
Waiting for pod advanced-policy-demo/access-472357175-y0m47 to be running, status is Pending, pod ready: false

If you don't see a command prompt, try pressing enter.

/ # wget -q --timeout=5 nginx -O -
wget: download timed out
/ #
```

We can also see that the two nginx pods are represented as [WorkloadEndpoints]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/workloadendpoint) in the Calico API.

```
calicoctl get workloadendpoint

NODE          ORCHESTRATOR   WORKLOAD                                     NAME
k8s-node-01   k8s            advanced-policy-demo.nginx-701339712-x1uqe   eth0
k8s-node-02   k8s            advanced-policy-demo.nginx-701339712-xeeay   eth0
k8s-node-01   k8s            kube-system.kube-dns-v19-mjd8x               eth0
```

Taking a closer look, we can see that they reference the correct profile for the Namespace,
and that the correct label information has been filled in.  Notice that the endpoint also
includes a special label `calico/k8s_ns`, which is automatically populated with the
pod's Kubernetes Namespace.

```
$ calicoctl get wep --workload advanced-policy-demo.nginx-701339712-x1uqe -o yaml
- apiVersion: v1
  kind: workloadEndpoint
  metadata:
    labels:
      calico/k8s_ns: advanced-policy-demo
      pod-template-hash: "701339712"
      run: nginx
    name: eth0
    node: k8s-node-01
    orchestrator: k8s
    workload: advanced-policy-demo.nginx-701339712-x1uqe
  spec:
    interfaceName: cali347609b8bd7
    ipNetworks:
    - 192.168.44.65/32
    mac: 56:b5:54:be:b2:a2
    profiles:
    - k8s_ns.advanced-policy-demo
```

### Define Kubernetes policy

We'll define some network policy through the Kubernetes API.  Run the following to create
a NetworkPolicy which allows traffic to nginx pods from any pods in the advanced-policy-demo Namespace.

```shell
kubectl create -f - <<EOF
kind: NetworkPolicy
apiVersion: extensions/v1beta1
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

It now shows up as a [Policy]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/policy) object in the Calico API.

```shell
$ calicoctl get policy -o wide
NAME                                ORDER   SELECTOR
advanced-policy-demo.access-nginx   1000    calico/k8s_ns == 'advanced-policy-demo' && run == 'nginx'
advanced-policy-demo.default-deny   1000    calico/k8s_ns == 'advanced-policy-demo'
```

After creating the policy, we can now access the nginx Service.  We also see that the pod can
access google.com on the public internet.  This is because we have not defined any egress policy.

```
$ kubectl run --namespace=advanced-policy-demo access --rm -ti --image busybox /bin/sh
Waiting for pod advanced-policy-demo/access-472357175-y0m47 to be running, status is Pending, pod ready: false

If you don't see a command prompt, try pressing enter.

/ # wget -q --timeout=5 nginx -O -
...
/ # ping google.com
PING google.com (216.58.219.206): 56 data bytes
64 bytes from 216.58.219.206: seq=0 ttl=61 time=14.365 ms
```

### Prevent outgoing connections from pods

Kubernetes NetworkPolicy does not provide a way to prevent outgoing connections from pods.  However,
Calico does. In this section we'll create a Policy using `calicoctl` which prevents all outgoing
connections from Kubernetes pods in the advanced-policy-demo Namespace.

To do this, we'll need to create a Policy which selects all pods in the Namespace, and denies
traffic that doesn't match another Pod in the Namespace.

```
calicoctl apply -f - <<EOF
apiVersion: v1
kind: policy
metadata:
  name: advanced-policy-demo.deny-egress
spec:
  selector: calico/k8s_ns == 'advanced-policy-demo'
  order: 500
  egress:
  - action: deny
    destination:
      notSelector: calico/k8s_ns == 'advanced-policy-demo'
EOF
```

Notice that we've specified an order of 500.  This means that this policy will be applied before any
of the Kubernetes policies.

We also need to create a policy which allows traffic to access kube-dns. Let's create one now in the kube-system Namespace.
We'll specify an order of 400 so that it takes precendent over other policies.

```
calicoctl apply -f - <<EOF
apiVersion: v1
kind: policy
metadata:
  name: advanced-policy-demo.allow-dns
spec:
  selector: calico/k8s_ns == 'advanced-policy-demo'
  order: 400
  egress:
  - action: allow
    protocol: udp
    destination:
      selector: calico/k8s_ns == 'kube-system' && k8s-app == 'kube-dns'
      ports: [53]
EOF
```

We should see now that traffic still works for pods within the Namespace, but we can no longer
access the public internet.

```
$ kubectl run --namespace=advanced-policy-demo access --rm -ti --image busybox /bin/sh
Waiting for pod advanced-policy-demo/access-472357175-y0m47 to be running, status is Pending, pod ready: false

If you don't see a command prompt, try pressing enter.

/ # wget -q --timeout=5 nginx -O -
...
/ # ping google.com
PING google.com (216.58.219.206): 56 data bytes
```

## Teardown

You can clean up after this guide by deleteing the advanced policy demo Namespace.

```
kubectl delete ns advanced-policy-demo
```

You will also need to delete the Calico policies that were created.

```
calicoctl delete policy advanced-policy-demo.deny-egress
calicoctl delete policy advanced-policy-demo.allow-dns
```
