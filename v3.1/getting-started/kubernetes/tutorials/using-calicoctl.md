---
title: Using calicoctl in Kubernetes
canonical_url: 'https://docs.projectcalico.org/v3.2/getting-started/kubernetes/tutorials/using-calicoctl'
---

`calicoctl` allows you to create, read, update, and delete {{site.prodname}} objects
from the command line. [Installing `calicoctl` as a binary](/{{page.version}}/usage/calicoctl/install#installing-calicoctl-as-a-binary-on-a-single-host) 
will provide you with maximum functionality, including access to the 
`node` commands. 

However, you can also [install `calicoctl` as a pod](/{{page.version}}/usage/calicoctl/install#installing-calicoctl-as-a-kubernetes-pod) and run `calicoctl` 
commands using `kubectl`:

```
$ kubectl exec -ti -n kube-system calicoctl -- /calicoctl get profiles -o wide
NAME                 TAGS
kns.default          kns.default
kns.kube-system      kns.kube-system
```

See the [calicoctl reference guide]({{site.baseurl}}/{{page.version}}/reference/calicoctl) 
for more information.
