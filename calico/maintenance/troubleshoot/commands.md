---
title: Troubleshooting commands
description: Learn basic commands to verify cluster and components are working. 
canonical_url: '/maintenance/troubleshoot/commands'
---

### Big picture

Use command line tools to get status and troubleshoot. 

- [Hosts](#hosts)
- [Kubernetes](#kubernetes)
- [Calico components](#calico-components)
- [Routing](#routing)
- [Network policy](#network-policy)

>**Note**: `calico-system` is used for operator-based commands and examples; for manifest-based install, use `kube-system`.
{: .alert .alert-info}

See [Calico architecture and components]({{site.baseurl}}/reference/architecture/overview) for help with components.

### Hosts

#### Verify number of nodes in a cluster

```bash
kubectl get nodes
```

```

NAME           STATUS   ROLES    AGE   VERSION
ip-10-0-0-10   Ready    master   27h   v1.18.0
ip-10-0-0-11   Ready    <none>   27h   v1.18.0
ip-10-0-0-12   Ready    <none>   27h   v1.18.0

```

#### Verify calico-node pods are running on every node, and are in a healthy state

```bash
kubectl get pods -n calico-system -o wide
```
```
NAME                        READY   STATUS    RESTARTS   AGE   IP             NODE           
calico-node-77zgj           1/1     Running   0          27h   10.0.0.10      ip-10-0-0-10   
calico-node-nz8k2           1/1     Running   0          27h   10.0.0.11      ip-10-0-0-11
calico-node-7trv7           1/1     Running   0          27h   10.0.0.12      ip-10-0-0-12 
```

#### Exec into pod for further troubleshooting

```bash
kubectl run multitool --image=praqma/network-multitool 

kubectl exec -it multitool -- bash
```
```
bash-5.0# ping 8.8.8.8
PING 8.8.8.8 (8.8.8.8) 56(84) bytes of data.
64 bytes from 8.8.8.8: icmp_seq=1 ttl=97 time=6.61 ms
64 bytes from 8.8.8.8: icmp_seq=2 ttl=97 time=6.64 ms
```

#### Collect {{site.prodname}} diagnostic logs

```bash
sudo calicoctl node diags
```

```
Collecting diagnostics
Using temp dir: /tmp/calico194224816
Dumping netstat
Dumping routes (IPv4)
Dumping routes (IPv6)
Dumping interface info (IPv4)
Dumping interface info (IPv6)
Dumping iptables (IPv4)
Dumping iptables (IPv6)

Diags saved to /tmp/calico194224816/diags-20201127_010117.tar.gz
```

### Kubernetes 

#### Verify all pods are running 

```bash
kubectl get pods -A
```

```
kube-system       coredns-66bff467f8-dxbtl                   1/1     Running   0          27h
kube-system       coredns-66bff467f8-n95vq                   1/1     Running   0          27h
kube-system       etcd-ip-10-0-0-10                          1/1     Running   0          27h
kube-system       kube-apiserver-ip-10-0-0-10                1/1     Running   0          27h
```

#### Verify Kubernetes API server is running

```bash
kubectl cluster-info
```
```
Kubernetes master is running at https://10.0.0.10:6443
KubeDNS is running at https://10.0.0.10:6443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy
ubuntu@master:~$ kubectl get svc
NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.49.0.1    <none>        443/TCP   2d2h
```

#### Verify Kubernetes kube-dns is working

```bash
kubectl get svc
```

```
NAME         TYPE        CLUSTER-IP   EXTERNAL-IP   PORT(S)   AGE
kubernetes   ClusterIP   10.49.0.1    <none>        443/TCP   2d2h
```

```bash
kubectl exec -it multitool  bash
```

```
bash-5.0# curl -I -k https://kubernetes
HTTP/2 403 
cache-control: no-cache, private
content-type: application/json
x-content-type-options: nosniff
content-length: 234
```

```bash
bash-5.0# nslookup google.com
```

```
Server:         10.49.0.10
Address:        10.49.0.10#53
Non-authoritative answer:
Name:   google.com
Address: 172.217.14.238
Name:   google.com
Address: 2607:f8b0:400a:804::200e
```

#### Verify that kubelet is running on the node with the correct flags

```bash
systemctl status kubelet
```
If there is a problem, check the journal

```bash
journalclt -u kubelet | head
```

#### Check the status of other system pods

Look especially at coredns; if they are not getting an IP, something is wrong with the CNI

```bash
kubectl get pod -n kube-system -o wide
```
But if other pods fail, it is likely a different issue. Perform normal Kubernetes troubleshooting. For example:

```bash
kubectl describe pod kube-scheduler-ip-10-0-1-20.eu-west-1.compute.internal -n kube-system | tail -15
``` 

### Calico components

#### View Calico CNI configuration on a node 

```bash
cat /etc/cni/net.d/10-calico.conflist
```

#### Verify calicoctl matches cluster

The cluster version and type must match the calicoctl version.

```bash
calicoctl version
```

For syntax:

```bash
calicoctl version -help
```

#### Check tigera operator status

```bash
kubectl get tigerastatus
```

```
NAME     AVAILABLE   PROGRESSING   DEGRADED   SINCE
calico   True        False         False      27h
```

#### Check if operator pod is running

```bash
kubectl get pod -n tigera-operator
```

#### View calico nodes

```bash
kubectl get pod -n calico-system -o wide
```

#### View {{site.prodname}} installation parameters

```bash
kubectl get installation -o yaml
```

```yaml
apiVersion: v1
items:
- apiVersion: operator.tigera.io/v1
  kind: Installation
  metadata:
    - apiVersion: operator.tigera.io/v1
 spec:
    calicoNetwork:
      bgp: Enabled
      hostPorts: Enabled
      ipPools:
      - blockSize: 26
        cidr: 10.48.0.0/16
        encapsulation: VXLANCrossSubnet
        natOutgoing: Enabled
        nodeSelector: all()
      multiInterfaceMode: None
      nodeAddressAutodetectionV4:
        firstFound: true
    cni:
      ipam:
        type: Calico
      type: Calico
```

#### Run commands across multiple nodes

Export THE_COMMAND_TO_RUN=date && for calinode in:

```bash
kubectl get pod -o wide -n calico-system | grep calico-node | awk '{print $1}'`; do echo $calinode; echo "-----"; 
```

```bash
kubectl exec -n calico-system $calinode -- $THE_COMMAND_TO_RUN; printf "\n"; done calico-node-8xfmx
```

```
-----
Defaulted container "calico-node" out of: calico-node, flexvol-driver (init), install-cni (init)
calico-node-9t8s7
-----
Defaulted container "calico-node" out of: calico-node, flexvol-driver (init), install-cni (init)
calico-node-9cjhw
-----
Defaulted container "calico-node" out of: calico-node, flexvol-driver (init), install-cni (init)
calico-node-cb7ff
-----
Defaulted container "calico-node" out of: calico-node, flexvol-driver (init), install-cni (init)
calico-node-qoxvw
-----
Defaulted container "calico-node" out of: calico-node, flexvol-driver (init), install-cni (init)
calico-node-wm5m2
-----
Defaulted container "calico-node" out of: calico-node, flexvol-driver (init), install-cni (init)
```

#### View pod info

```bash
kubectl describe pods `<pod_name>`  -n `<namespace> `
```

```bash
kubectl describe pods busybox -n default
```

```
Events:
  Type    Reason     Age   From                   Message
  ----    ------     ----  ----                   -------
  Normal  Scheduled  21s   default-scheduler      Successfully assigned default/busybox to ip-10-0-0-11
  Normal  Pulling    20s   kubelet, ip-10-0-0-11  Pulling image "busybox"
  Normal  Pulled     19s   kubelet, ip-10-0-0-11  Successfully pulled image "busybox"
  Normal  Created    19s   kubelet, ip-10-0-0-11  Created container busybox
  Normal  Started    18s   kubelet, ip-10-0-0-11  Started container busybox
```

#### View logs of a pod

```bash
kubectl logs `<pod_name>`  -n `<namespace>`
```

```bash
kubectl logs busybox -n default
```

#### View kubelet logs

```bash
journalctl -u kubelet
```

### Routing

#### Verify routing table on the node

```bash
ip route
```

```
default via 10.0.0.1 dev eth0 proto dhcp src 10.0.0.10 metric 100 
10.0.0.0/24 dev eth0 proto kernel scope link src 10.0.0.10 
10.0.0.1 dev eth0 proto dhcp scope link src 10.0.0.10 metric 100 
10.48.66.128/26 via 10.0.0.12 dev eth0 proto 80 onlink 
10.48.231.0/26 via 10.0.0.11 dev eth0 proto 80 onlink 
172.17.0.0/16 dev docker0 proto kernel scope link src 172.17.0.1 linkdown
```

#### Verify BGP peer status

```bash
sudo calicoctl node status
```

```
Calico process is running.

IPv4 BGP status
+--------------+-------------------+-------+------------+-------------+
| PEER ADDRESS |     PEER TYPE     | STATE |   SINCE    |    INFO     |
+--------------+-------------------+-------+------------+-------------+
| 10.0.0.12    | node-to-node mesh | up    | 2020-11-25 | Established |
| 10.0.0.11    | node-to-node mesh | up    | 2020-11-25 | Established |
+--------------+-------------------+-------+------------+-------------+
```

#### Verify overlay configuration

```bash
kubectl get ippools default-ipv4-ippool -o yaml
```

```yaml
...
spec:
  ipipMode: Always
  vxlanMode: Never
...
```

#### Verify bgp learned routes

```bash
ip r | grep bird
```

```
192.168.66.128/26 via 10.0.0.12 dev tunl0 proto bird onlink 
192.168.180.192/26 via 10.0.0.10 dev tunl0 proto bird onlink 
blackhole 192.168.231.0/26 proto bird 
```

#### Verify BIRD routing table

**Note**: The BIRD routing table gets pushed to node routing tables.

```bash
kubectl exec -it -n calico-system calico-node-8cfc8 -- /bin/bash
```

```
[root@ip-10-0-0-11 /]# birdcl
BIRD v0.3.3+birdv1.6.8 ready.
bird> show route
0.0.0.0/0          via 10.0.0.1 on eth0 [kernel1 18:13:33] * (10)
10.0.0.0/24        dev eth0 [direct1 18:13:32] * (240)
10.0.0.1/32        dev eth0 [kernel1 18:13:33] * (10)
10.48.231.2/32     dev calieb874a8ef0b [kernel1 18:13:41] * (10)
10.48.231.1/32     dev caliaeaa173109d [kernel1 18:13:35] * (10)
10.48.231.0/26     blackhole [static1 18:13:32] * (200)
10.48.231.0/32     dev vxlan.calico [direct1 18:13:32] * (240)
10.48.180.192/26   via 10.0.0.10 on eth0 [Mesh_10_0_0_10 18:13:34] * (100/0) [i]
                   via 10.0.0.10 on eth0 [Mesh_10_0_0_12 18:13:41 from 10.0.0.12] (100/0) [i]
                   via 10.0.0.10 on eth0 [kernel1 18:13:33] (10)
10.48.66.128/26    via 10.0.0.12 on eth0 [Mesh_10_0_0_10 18:13:36 from 10.0.0.10] * (100/0) [i]
                   via 10.0.0.12 on eth0 [Mesh_10_0_0_12 18:13:41] (100/0) [i]
                   via 10.0.0.12 on eth0 [kernel1 18:13:36] (10)
```

#### Capture traffic

For example, 

```bash
sudo tcpdump -i calicofac0017c3 icmp
```

### Network policy

#### Verify existing Kubernetes network policies

```bash
kubectl get networkpolicy --all-namespaces
```

```
NAMESPACE   NAME             POD-SELECTOR   AGE
client      allow-ui         <none>         20m
client      default-deny     <none>         4h51m
stars       allow-ui         <none>         20m
stars       backend-policy   role=backend   20m
stars       default-deny     <none>         4h51m
```

#### Verify existing {{site.prodname}} network policies

```bash
calicoctl get networkpolicy --all-namespaces -o wide
```

```
NAMESPACE     NAME                         ORDER   SELECTOR                                                       
calico-demo   allow-busybox                50      app == 'porter'                                                
client        knp.default.allow-ui         1000    projectcalico.org/orchestrator == 'k8s'                        
client        knp.default.default-deny     1000    projectcalico.org/orchestrator == 'k8s'                        
stars         knp.default.allow-ui         1000    projectcalico.org/orchestrator == 'k8s'                        
stars         knp.default.backend-policy   1000    projectcalico.org/orchestrator == 'k8s' 
stars         knp.default.default-deny     1000    projectcalico.org/orchestrator == 'k8s'                        
```

#### Verify existing {{site.prodname}} global network policies

```bash
calicoctl get globalnetworkpolicy -o wide
```

```
NAME                  ORDER   SELECTOR
default-app-policy    100
egress-lockdown       600
default-node-policy   100     has(kubernetes.io/hostname)
nodeport-policy       100     has(kubernetes.io/hostname)
```

#### Check policy selectors and order

For example,

```bash
calicoctl get np -n yaobank -o wide
```

If the selectors should match, check the endpoint IP and the node where it is running. For example, 

```bash
kubectl get pod -l app=customer -n yaobank
```
