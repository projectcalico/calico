---
title: Using Host Endpoints with Kubernetes
---

When [Using Calico to Secure Host Interfaces]({{site.baseurl}}/{{page.version}}/getting-started/bare-metal/bare-metal) 
by setting up [Host Endpoints]({{site.baseurl}}/{{page.version}}/reference/calicoctl/resources/hostendpoint) 
there are some additional considerations needed when using Kubernetes.

### Allowing forwarded traffic in Host Endpoint Policy

Since version v2.1.0 of Calico, Host Endpoint(HEP) policies apply to forwarded
traffic.  Due to the forwarding that kubernetes sets up through kube-proxy,
to handle its service IPs and NodePorts, it is necessary to add policy to allow
forwarded traffic to the pod CIDR(s) in the HEP.  The forwarding is allowed
with a policy similar to the following, with the appropriate selector to apply
to all Kubernetes Host Endpoints and the `net` matching your configured IP Pool.

```
- apiVersion: v1
  kind: policy
  metadata:
    name: allow-forward
  spec:
    selector: "hosts=='k8sNodes'"
    order: 2
    ingress:
    - action: allow
      destination:
        net: "192.168.0.0/16"
```

### Allowing Ip-in-IP traffic

Many setups require IP-in-IP and policy must be added to allow Host Endpoints to
receive the IP-in-IP traffic that will be generated as packets move between
hosts.
Allowing IP-in-IP traffic is achieved with a policy similar to the following
with the appropriate selector to apply to all Kubernetes Host Endpoints.

```
- apiVersion: v1
  kind: policy
  metadata:
    name: allow-ipip
  spec:
    selector: "hosts=='k8sNodes'"
    order: 3
    ingress:
    - action: allow
      protocol: 4
```
