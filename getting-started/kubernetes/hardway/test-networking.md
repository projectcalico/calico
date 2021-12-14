---
title: Test networking
description: Test that networking works correctly.
canonical_url: '/getting-started/kubernetes/hardway/test-networking'
---

In this lab we will test the {{site.prodname}} cluster to demonstrate networking is working correctly.

## Pod to pod pings

Create three busybox instances

```bash
kubectl create deployment pingtest --image=busybox --replicas=3 -- sleep infinity
```

Check their IP addresses

```bash
kubectl get pods --selector=app=pingtest --output=wide
```

Result

```
NAME                      READY   STATUS    RESTARTS   AGE     IP               NODE               NOMINATED NODE   READINESS GATES
pingtest-b4b6f8cf-b5z78   1/1     Running   0          3m28s   192.168.38.128   ip-172-31-37-123   <none>           <none>
pingtest-b4b6f8cf-jmzq6   1/1     Running   0          3m28s   192.168.45.193   ip-172-31-40-217   <none>           <none>
pingtest-b4b6f8cf-rn9nm   1/1     Running   0          3m28s   192.168.60.64    ip-172-31-45-29    <none>           <none>
```
{: .no-select-button}

Note the IP addresses of the second two pods, then exec into the first one. For example

```bash
kubectl exec -ti pingtest-b4b6f8cf-b5z78 -- sh
```

From inside the pod, ping the other two pod IP addresses. For example

```bash
ping 192.168.45.193 -c 4
```

Result

```
PING 192.168.45.193 (192.168.45.193): 56 data bytes
64 bytes from 192.168.45.193: seq=0 ttl=62 time=1.847 ms
64 bytes from 192.168.45.193: seq=1 ttl=62 time=0.684 ms
64 bytes from 192.168.45.193: seq=2 ttl=62 time=0.488 ms
64 bytes from 192.168.45.193: seq=3 ttl=62 time=0.442 ms

--- 192.168.45.193 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max = 0.442/0.865/1.847 ms
```
{: .no-select-button}

## Check routes

From one of the nodes, verify that routes exist to each of the `pingtest` pods' IP addresses. For example

```bash
ip route get 192.168.38.128
```

Result

```
192.168.38.128 via 172.31.37.123 dev eth0 src 172.31.42.47 uid 1000
    cache
```
{: .no-select-button}

The `via 172.31.37.123` in this example indicates the next-hop for this pod IP, which matches the IP address of the node the
pod is scheduled on, as expected.

## IPAM allocations from different pools

Recall that we created two IP pools, but left one disabled.

```bash
calicoctl get ippools -o wide
```

Result

```
NAME    CIDR               NAT    IPIPMODE   VXLANMODE   DISABLED   SELECTOR
pool1   192.168.0.0/18     true   Never      Never       false      all()
pool2   192.168.192.0/19   true   Never      Never       true       all()
```
{: .no-select-button}

Enable the second pool.

```bash
calicoctl apply -f - <<EOF
apiVersion: projectcalico.org/v3
kind: IPPool
metadata:
  name: pool2
spec:
  cidr: 192.168.192.0/19
  ipipMode: Never
  natOutgoing: true
  disabled: false
  nodeSelector: all()
EOF
```

Create a pod, explicitly requesting an address from `pool2`

```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: pingtest-pool2
  annotations:
    cni.projectcalico.org/ipv4pools: "[\"pool2\"]"
spec:
  containers:
  - args:
    - sleep
    - infinity
    image: busybox
    imagePullPolicy: Always
    name: pingtest
EOF
```

Verify it has an IP address from `pool2`

```bash
kubectl get pod pingtest-pool2 -o wide
```

Result
```
NAME             READY   STATUS    RESTARTS   AGE   IP              NODE              NOMINATED NODE   READINESS GATES
pingtest-pool2   1/1     Running   0          75s   192.168.219.0   ip-172-31-45-29   <none>           <none>
```
{: .no-select-button}

From one of the original pingtest pods, ping the IP address.

```bash
ping 192.168.219.0 -c 4
```

Result
```
PING 192.168.219.0 (192.168.219.0): 56 data bytes
64 bytes from 192.168.219.0: seq=0 ttl=62 time=0.524 ms
64 bytes from 192.168.219.0: seq=1 ttl=62 time=0.459 ms
64 bytes from 192.168.219.0: seq=2 ttl=62 time=0.505 ms
64 bytes from 192.168.219.0: seq=3 ttl=62 time=0.492 ms

--- 192.168.219.0 ping statistics ---
4 packets transmitted, 4 packets received, 0% packet loss
round-trip min/avg/max = 0.459/0.495/0.524 ms
```
{: .no-select-button}

## Clean up

```bash
kubectl delete deployments.apps pingtest
kubectl delete pod pingtest-pool2
```

## Next

[Test network policy](./test-network-policy)
