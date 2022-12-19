---
title: VPP dataplane troubleshooting
description: Specific troubleshooting steps for the VPP dataplane.
canonical_url: '/maintenance/troubleshoot/vpp'
---

### Big picture

This page describes the troubleshooting steps for the [VPP dataplane]({{ site.baseurl }}/getting-started/kubernetes/vpp/getting-started). If you did not configure the VPP dataplane, this page is not for you!

If you're encountering issues with the VPP dataplane, feel free to reach out to us either on the [#vpp channel](https://calicousers.slack.com/archives/C017220EXU1) on the {{ site.prodname }} slack, or by opening a new issue in [Github](https://github.com/projectcalico/vpp-dataplane/issues)).

### Installing calivppctl

`calivppctl` is a helper bash script shipped alongside vpp container images. It can be installed to your host with the following methods, and helps collecting logs and debugging a running cluster with the VPP dataplane installed.

* With curl
````bash
curl https://raw.githubusercontent.com/projectcalico/vpp-dataplane/{{page.vppbranch}}/test/scripts/vppdev.sh \
  | tee /usr/bin/calivppctl
chmod +x /usr/bin/calivppctl
````
* With docker (and a cluster with calico-vpp running)
````bash
vppcontainer=$(docker ps | grep vpp_calico-vpp | awk '{ print $1 }')
docker cp ${vppcontainer}:/usr/bin/calivppctl /usr/bin/calivppctl
````
* With kubectl (and a cluster with calico-vpp running)
````bash
vpppod=$(kubectl -n calico-vpp-dataplane get pods -o wide | grep calico-vpp-node- | awk '{ print $1 }' | head -1)
kubectl -n calico-vpp-dataplane exec -it ${vpppod} -c vpp -- cat /usr/bin/calivppctl | tee /usr/bin/calivppctl > /dev/null
chmod +x /usr/bin/calivppctl
````

### Troubleshooting

#### Kubernetes Cluster

First you need to make sure Kubernetes is up and running.
- `service kubelet status` should give you a first hint.
- Issues should be reported in the kubelet logs, which you can check with this command if you are using systemd: `journalctl -u kubelet -r -n200`

 >**Note** Kubernetes does not run with swap enabled.
{: .alert .alert-info}

#### Starting calico-vpp-node Daemon set

Once the cluster is correctly started, the next issue can come from the Daemonset configuration.
Best is to start by inspecting the pods : are they running correctly ?
Usually configuration issues (available hugepages, memory, ...) will be reported here
````bash
kubectl -n calico-vpp-dataplane describe pod/calico-vpp-node-XXXXX
````

 >**Note** If at this point you don't have enough hugepages, you'll have to restart kubelet
after allocating them for taking it into account (using for instance `service kubelet restart`)
{: .alert .alert-info}

#### Having VPP up and running

Once the pods don't report any issue, the pods should have started. There are two
containers for each node : VPP that starts the vpp process and setups connectivity,
and the agent handling pod connectivity, service load balancing, BGP, policies, etc.

First check that VPP is running correctly. If the connectivity configuration, interface naming
is not correct, this will be reported here. Once this is running, you should be able to ping your other nodes through VPP.
````bash
# Print VPP's log : basic connectivity and NIC configuration
calivppctl log -vpp myk8node1
````

Then you can check for any issues reported by the Agent (e.g. BGP listen issue
if the port is already taken, or missing configuration pieces). If this doesn't
show any errors, you should be able to `nslookup kubernetes.default` from pods.
````bash
# Print the logs for the {{ site.prodname }} VPP dataplane agent, programming serviceIPs, BGP, ...
calivppctl log -agent myk8node1
````

If all this doesn't play well you can always use the export to generate an export.tar.gz
bundle and ask for help on the [#vpp channel](https://calicousers.slack.com/archives/C017220EXU1)
````bash
calivppctl export
````

### Accessing the VPP cli

For further debugging, tracing packets and inspecting VPP's internals, you can
get a vpp shell using the following
````bash
calivppctl vppctl myk8node1
````

#### Listing interfaces and basics

To list existing interfaces and basic counters use
````
vpp# show int
vpp# show int addr
````
To get more insights on the main interface (e.g. if you're using dpdk) you can check
for errors & drops in
````
vpp# show hardware-interfaces
````
Other places to look for errors
````
vpp# show log       # VPP startup log
vpp# show err       # Prints out packet counters (not always actual errors, but includes drops)
vpp# show buffers   # You should have non zero free buffers, otherwise traffic won't flow
````

### Tracing packets

#### Internal network layout

For starters, here is a small schematic of how the network looks like:
![k8-calico-vpp]({{site.baseurl}}/images/vpp-tracing-net.svg)

Container interfaces are named `tun[0-9]+`. You can find which one belong to which container as follows.
````
# Connect to vppctl
$ calivppctl vppctl NODENAME

# List interfaces
vpp# show interface
              Name               Idx    State  MTU (L3/IP4/IP6/MPLS)     Counter          Count
avf-0/d8/a/0                      1      up          9000/0/0/0     tx packets                     2
                                                                    tx bytes                     216
local0                            0     down          0/0/0/0
tap0                              2      up           0/0/0/0       rx packets                     9
[...]
tun3                              5      up           0/0/0/0       rx packets                     5
                                                                    rx bytes                     431
                                                                    tx packets                     5
                                                                    tx bytes                     387
                                                                    ip4                            5

# Show the route for address 11.0.166.132
vpp# show ip fib 11.0.166.132
ipv4-VRF:0, fib_index:0, flow hash:[src dst sport dport symmetric ] epoch:0 flags:none locks:[adjacency:1, default-route:1, ]
11.0.166.132/32 fib:0 index:19 locks:5
  cnat refs:1 entry-flags:uRPF-exempt,interpose, src-flags:added,contributing,active, cover:-1 interpose:
      [@0]: [4] cnat-client:[11.0.166.132] tr:0 sess:1
    path-list:[26] locks:3 flags:shared, uPRF-list:24 len:1 itfs:[5, ]
      path:[32] pl-index:26 ip4 weight=1 pref=0 attached-nexthop:  oper-flags:resolved, cfg-flags:attached,
        11.0.166.132 tun3 (p2p)
      [@0]: ipv4 via 0.0.0.0 tun3: mtu:9000 next:7
  [...]

# This one is behind `tun3`
# If you want more info about this interface (name in Linux, queues, descriptors, ...)
vpp# show tun tun3
Interface: tun3 (ifindex 5)
  name "eth0"
  host-ns "/proc/17675/ns/net"
  [...]
````
`tap0` is the interface providing connectivity to the host, using the original interface name on the Linux side (use `show tap tap0` and `show ip punt redirect`).

#### Capturing traffic inside the cluster

Let's take the case of two pods talking to each other in your cluster (see the schema above).
You might want to inspect the traffic at 3 different locations :
* as it exits the pod (in Linux inside the first pod)
* as it goes through VPP
* as it is received in the second pod (in Linux again)

We cover the three cases, first inside VPP (depending on where your traffic is coming from : a pod or outside your host)
then inside your pods (usually with tcpdump)

#### Traffic capture inside VPP

##### Traffic from a pod

The following snippet will allow you to capture all traffic coming from containers on a particular node, grep from a specific packet,
and see what happened to it.
````bash
# Make sure that the trace buffer is clean in VPP
calivppctl vppctl NODENAME clear trace
# Add a trace from the virtio-input input-node
calivppctl vppctl NODENAME trace add virtio-input 500
# generate some traffic
calivppctl vppctl NODENAME show trace max 500 > somefile
# Grep for your IPs
cat somefile | grep '1.2.3.4 -> 5.6.7.8' -A40 -B40
````

Output looks quite cumbersome at first as it contains the whole path of a packet through VPP, from reception to tx.

````
vpp# show trace
Packet 1

00:09:46:518858: virtio-input
# This packet has been received on the interface number #2 (column Idx in `show int`)
# and is 688 Bytes long
  virtio: hw_if_index 2 next-index 1 vring 0 len 688
    hdr: flags 0x00 gso_type 0x00 hdr_len 0 gso_size 0 csum_start 0 csum_offset 0 num_buffers 1
00:09:46:518866: ip4-input
# we read TCP header, addresses and ports
  TCP: 20.0.0.1 -> 11.0.166.133
    tos 0x00, ttl 64, length 688, checksum 0x1bc5 dscp CS0 ecn NON_ECN
    fragment id 0x56fd, flags DONT_FRAGMENT
  TCP: 6443 -> 34112
    seq. 0xa1f93599 ack 0x818eb1c1
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x00b7
00:09:46:518870: ip4-lookup
  fib 0 dpo-idx 5 flow hash: 0x00000000
  TCP: 20.0.0.1 -> 11.0.166.133
    tos 0x00, ttl 64, length 688, checksum 0x1bc5 dscp CS0 ecn NON_ECN
    fragment id 0x56fd, flags DONT_FRAGMENT
  TCP: 6443 -> 34112
    seq. 0xa1f93599 ack 0x818eb1c1
    flags 0x18 PSH ACK, tcp header: 32 bytes
    window 502, checksum 0x00b7
00:09:46:518873: ip4-cnat-tx
# We need to do some NATing as it's Kubernetes
  found: session:[20.0.0.1;6443 -> 11.0.166.133;34112, TCP] => 11.96.0.1;443 -> 11.0.166.133;34112 lb:-1 age:4190
00:09:46:518879: ip4-rewrite
# We rewrite the ip packet
# mac addresses only when coming / going to a PHY, as tun interfaces are L3-only
  tx_sw_if_index 6 dpo-idx 7 : ipv4 via 0.0.0.0 tun4: mtu:9000 next:8 flow hash: 0x00000000
  00000000: 450002b056fd40003f0625650b6000010b00a68501bb8540a1f93599818eb1c1
  00000020: 801801f620c700000101080a3f906c98fbaaba031703030277413d39
# Output happens on the interface `tun4`
00:09:46:518880: tun4-output
  tun4
  00000000: 450002b056fd40003f0625650b6000010b00a68501bb8540a1f93599818eb1c1
  00000020: 801801f620c700000101080a3f906c98fbaaba031703030277413d39b97817c1
  00000040: 41392fdbe0e9d4886849851476cdb8986362ee2f789bfefd8a5c106c898d1309
  00000060: 4f8f8cb89159d99e986813a48d91334930eb5eb10ca4248c
00:09:46:518881: tun4-tx
    buffer 0x24cf615: current data 0, length 688, buffer-pool 1, ref-count 1, totlen-nifb 0, trace handle 0x1000000
  ipv4 tcp hdr-sz 52 l2-hdr-offset 0 l3-hdr-offset 0 l4-hdr-offset 20 l4-hdr-sz 32
  0x0b60: 40:00:3f:06:25:65 -> 45:00:02:b0:56:fd

Packet 2
[...]
````

##### Traffic from the phy

If you want to capture traffic coming from the physical NIC, you should use `trace add` but with a different source node a.k.a `dpdk-input` `af-packet-input` `af_xdp-input` `avf-input` instead of `virtio-input`.

`show run` should give you a hint of the `X-input` node you want to trace from.

````
vpp# show run
Thread 1 vpp_wk_0 (lcore 25)
Time 1.9, 10 sec internal node vector rate 1.05 loops/sec 1074819.68
  vector rates in 7.5356e0, out 7.5356e0, drop 0.0000e0, punt 0.0000e0
             Name                 State         Calls          Vectors        Suspends         Clocks       Vectors/Call
avf-input                        polling           2233530               0               0          8.24e1            0.00
ip4-cnat-snat                    active                  1               1               0          5.35e3            1.00
ip4-cnat-tx                      active                 14              15               0          1.18e3            1.07
[...]

# Here we seem to want to use trace add avf-input 200
````

Same as with traffic from a container, you can use
````bash
# Make sure that the trace buffer is clean in VPP
calivppctl vppctl NODENAME clear trace
# Add a trace from the virtio-input input-node
calivppctl vppctl NODENAME trace add avf-input 500
# generate some traffic
calivppctl vppctl NODENAME show trace max 500 > somefile
# Grep for your IPs
cat somefile | grep '1.2.3.4 -> 5.6.7.8' -A40 -B40
````

##### With Wireshark

Alternatively to the trace, you can do a capture and analyze it inside Wireshark. You can do this with:
````
vpp# pcap dispatch trace on max 1000 file vppcapture buffer-trace dpdk-input 1000
vpp# pcap dispatch trace off
````
This will generate a file named `/tmp/vppcapture`

Then on your host run:
````bash
calivppctl sh vpp NODENAME
root@server:~# mv /tmp/vppcapture /var/lib/vpp/
root@server:~# exit
# The file should now be at /var/lib/vpp/vppcapture on your host 'NODENAME'
````

You can then `scp NODENAME:/var/lib/vpp/vppcapture .` on your machine and open it with Wireshark
[More info about this here](https://haryachyy.wordpress.com/2019/09/29/learning-vpp-trace-with-wireshark/)

#### Traffic received in the pods

To inspect traffic actually received by the pods (if `tcpdump` is installed in the pod), simply run `tcpdump -ni eth0` inside the pod. If tcpdump is not available in the pod, here are two options to still be able to capture pod traffic:

##### Tcpdump is available on the host

Provided that you have `tcpdump` installed on the host, you can use `nsenter` to attach to the pod's network namespace and use the host's `tcpdump` on the container's interface.

This works on docker as follows :
````bash
{% raw %}
# Find the container ID you want to inspect
$ docker ps
CONTAINER ID        IMAGE                        COMMAND                CREATED              STATUS              PORTS               NAMES
4c01db0b339c        ubuntu:12.04                 bash                   17 seconds ago       Up 16 seconds       3300-3310/tcp       webapp

# Get the container PID out of it
$ docker inspect --format '{{ .State.Pid }}' 4c01db0b339c
12345

# Attach
$ nsenter -t 12345 -n bash
{% endraw %}
````

##### No tcpdump, but we have python !

Open an AF_PACKET socket in python with the following code
and run it attached to the running namespace as previously.
````python
#!/usr/bin/env python
from socket import *
from struct import unpack

IFNAME = "eth0"
N_PKT = 50
MTU=1500

sock = socket(AF_PACKET, SOCK_DGRAM, 0x0800)
sock.bind((IFNAME, 0x0800))
for _ in range(N_PKT):
    data = sock.recvfrom(MTU, 0)[0]
    src_addr = inet_ntop(AF_INET, data[12:16])
    dst_addr = inet_ntop(AF_INET, data[16:20])
    src_port, = unpack("!H", data[20:22])
    dst_port, = unpack("!H", data[22:24])
    data_len, = unpack("!H", data[24:26])
    cksum, = unpack("!H", data[26:28])

    print("%s:%d -> %s:%d len %d cs %d" % (src_addr, src_port, dst_addr, dst_port, data_len, cksum))
````
This requires privileges and thus is usually easier to run from the host. From the host, you can use `echo "the python blob above" | nsenter -t <thePID> -n python` to execute this code.

#### Traffic to the kubelet agent

As the kubelet agent runs directly on the host without a network namespace, pods talking to it (e.g. coredns resolvers) would go through a specific path. Packets destined to it will be caught by VPP's punt mechanism, and will be forwarded to the host through a tap interface which will have the same name as the original interface in Linux.

To debug traffic within VPP, use the trace & check that traffic is correctly punted to the tap0 interface.

On the host, you can use `tcpdump` normally to check the traffic.

### Crashes & coredumps

In order to instruct vpp to leave a coredump in the event of a crash, you can pass the `CALICOVPP_CORE_PATTERN` environment variable to the vpp container:
````yaml
kind: DaemonSet
apiVersion: apps/v1
metadata:
  name: calico-vpp-node

...

    - name: vpp
      env:
      - name: CALICOVPP_CORE_PATTERN
        value: "/home/hostuser/vppcore.%e.%p"
      volumeMounts:
      - name: userhome
        mountPath: /home/hostuser

...

volumes:
- name: userhome
  hostPath:
    path: ${SOME_DIRECTORY}
````

This will generate a `vppcore.vpp_main.<pid>` file in `${DIR}` if vpp aborts unexpectedly. If you encounter this situation, please note the exact version of the vpp image that generated the corefile (using the image hash) to facilitate further troubleshooting.

To explore it run:

````bash
docker run -it --entrypoint=bash -v $DIR/vppcore.vpp_main.12345:/root/vppcore calicovpp/vpp:VERSION
# You should have a shell inside the vpp container
apt update && apt install -y gdb
gdb vpp ./vppcore
````

