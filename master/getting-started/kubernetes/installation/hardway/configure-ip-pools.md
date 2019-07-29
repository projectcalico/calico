---
title: Configure IP pools
canonical_url: 'https://docs.projectcalico.org/master/getting-started/kubernetes/installation/hardway/configure-ip-pools'
---

A *workload* is a container or VM that {{site.prodname}} handles the virtual networking for. In Kubernetes, workloads are Pods.
A **Workload Endpoint** is the virtual network interface a workload uses to connect to the {{site.prodname}} network.

**IP Pools** are ranges of IP addresses that {{site.prodname}} uses for **Workload Endpoints**.

When we stood up the Kubernetes cluster, we set the Pod CIDR, which is the range of IP addresses Kubernetes thinks
the pods should be in.  Many Kubernetes components use this setting to determine if an IP belongs to a pod, so you
normally want all IP Pools you configure to be subsets of the Pod CIDR.

Let's define two IP Pools for use in this cluster.  You can have a production-ready {{site.prodname}} install with only a single
pool, but we define two so that we can show advanced networking later in this guide.

```
cat > pool1.yaml <<EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: pool1
spec:
  cidr: 192.168.0.0/18
  ipipMode: Never
  natOutgoing: true
  disabled: false
  nodeSelector: all()
EOF
```

The Pod CIDR was `192.168.0.0/16`.  The `/16` means 16 bits of a 32-bit IPv4 address is the fixed prefix, therefore
16 bits are freely variable within the CIDR, or about 64K addresses.  For our first IPPool, we define the prefix
`192.168.0.0/18`, leaving only 14 bits free, or about 16K addresses for pods.  This is enough for a very large
Kubernetes cluster, and it still leaves a lot of room in the Pod CIDR if we want to create some more IP Pools.

Let's define a second pool right now.

```
cat > pool2.yaml <<EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: pool2
spec:
  cidr: 192.168.192.0/19
  ipipMode: Never
  natOutgoing: true
  disabled: true
  nodeSelector: all()
EOF
```

In this second pool, we set `disabled` to `true`, meaning that {{site.prodname}} will not create new pods with addresses in the pool
but will still recognize pods with these addresses as part of the {{site.prodname}} network. Later, in the
[test networking](./test-networking) lab, we will enable this pool and demonstrate how to control which pools your pods are assigned
addresses from.

The `nodeSelector` is a label selector which determines which nodes use the pool. They are both set to `all()` meaning all
nodes can use the pools.

Add these pools to {{site.prodname}}

```
calicoctl create -f pool1.yaml
calicoctl create -f pool2.yaml
```

Verify the pools are created by

```
calicoctl get ippools
```

You should see output similar to 

```
NAME    CIDR               SELECTOR   
pool1   192.168.0.0/18     all()      
pool2   192.168.192.0/19   all()
```

## Next

[Install CNI Plugin](./install-cni-plugin)