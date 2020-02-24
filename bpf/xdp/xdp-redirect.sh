#!/bin/bash

set -e

ip link del wl1-host || true
ip link del wl2-host || true
ip netns del workload1 || true
ip netns del workload2 || true

ip netns add workload1
ip netns add workload2

ip link add name wl1-host type veth peer name wl1-wl

ip link add name wl2-host type veth peer name wl2-wl

# Fudge the MACs so that we can configure static mappings below.
ip link set wl1-host addr 02:D6:C9:33:AB:60
ip link set wl1-wl addr 02:D6:C9:33:AB:61
ip link set wl2-host addr 02:D6:C9:33:AB:62
ip link set wl2-wl addr 02:D6:C9:33:AB:63

sysctl -w net.ipv4.conf.wl1-host.forwarding=1
sysctl -w net.ipv4.conf.wl2-host.forwarding=1

ip link set netns workload1 wl1-wl
ip link set netns workload2 wl2-wl

ip netns exec workload1 ip link set up wl1-wl
ip netns exec workload1 ip link set up lo
ip netns exec workload1 ip addr add 192.168.100.2 dev wl1-wl
ip netns exec workload1 ip route add 192.168.100.1 dev wl1-wl src 192.168.100.2
ip netns exec workload1 ip route add 0.0.0.0/0 via 192.168.100.1

ip netns exec workload2 ip link set up wl2-wl
ip netns exec workload2 ip link set up lo
ip netns exec workload2 ip addr add 192.168.100.3 dev wl2-wl
ip netns exec workload2 ip route add 192.168.100.1 dev wl2-wl src 192.168.100.3
ip netns exec workload2 ip route add 0.0.0.0/0 via 192.168.100.1

ip link set up wl1-host
ip link set up wl2-host

ip addr add 192.168.100.1 dev wl1-host nodad
ip addr add 192.168.100.1 dev wl2-host nodad

ip route add 192.168.100.2 dev wl1-host src 192.168.100.1
ip route add 192.168.100.3 dev wl2-host src 192.168.100.1

arp -s -i wl1-host 192.168.100.2 02:D6:C9:33:AB:61
arp -s -i wl2-host 192.168.100.3 02:D6:C9:33:AB:63
ip netns exec workload1 arp -s -i wl1-wl 192.168.100.1 02:D6:C9:33:AB:60
ip netns exec workload2 arp -s -i wl2-wl 192.168.100.1 02:D6:C9:33:AB:62

iptables -D FORWARD -i wl+ -j ACCEPT || true
iptables -A FORWARD -i wl+ -j ACCEPT || true

#ip netns exec workload1 iptables -t mangle -A POSTROUTING -p udp -j CHECKSUM --checksum-fill

make bpf/xdp/generated/mac_sw_redir.o

obj=bpf/xdp/generated/mac_sw_redir.o
bpf_dir=/sys/fs/bpf/xdp/mac_sw_redir
map_dir=$bpf_dir/maps

rm -fr $bpf_dir

# Load the object file, pinning each of its entrypoints and maps to a particular name in the file system.
bpftool prog loadall \
    $obj \
    $bpf_dir \
    type xdp \
    pinmaps $map_dir

# Attach the switching entrypoint to the host side of the veths.
ip link set dev wl1-host xdpdrv pinned $bpf_dir/mac_sw_redir
ip link set dev wl2-host xdpdrv pinned $bpf_dir/mac_sw_redir

# Attach a dummy, allow-all, program to the inside of each veth.  This is required by the veth implementation of XDP.
# Note: the netns doesn't inherit the BPF filesystem so we can't use the pinned version here (without more work to
# mount that in).
ip netns exec workload1 ip link set dev wl1-wl xdpdrv obj bpf/xdp/generated/mac_sw_redir.o sec allow_all
ip netns exec workload2 ip link set dev wl2-wl xdpdrv obj bpf/xdp/generated/mac_sw_redir.o sec allow_all


# Add the two veths to the interface map so we can use them with redirect_map().
veth_id=$(ip link show wl1-host | grep -o '^[0-9]\+')
bpftool map update pinned $map_dir/calico_ifaces_map key 0 0 0 0 value $((veth_id & 0xff)) $((veth_id >> 8)) 0 0
veth_id=$(ip link show wl2-host | grep -o '^[0-9]\+')
bpftool map update pinned $map_dir/calico_ifaces_map key 1 0 0 0 value $((veth_id & 0xff)) $((veth_id >> 8)) 0 0

# Add the MAC switching data to the map.
bpftool map update pinned $map_dir/calico_mac_sw_map key 192 168 100 2 value hex \
    02 D6 C9 33 AB 60 \
    02 D6 C9 33 AB 61 \
    00 00 00 00
bpftool map update pinned $map_dir/calico_mac_sw_map key 192 168 100 3 value hex \
    02 D6 C9 33 AB 62 \
    02 D6 C9 33 AB 63 \
    01 00 00 00


#
#echo
#echo "Running netcat"
#echo
#ip netns exec workload2 nc -l -u 192.168.100.3 5000 | sed -e 's/^/Netcat received: /' &
#
#while true;
#do
#  echo "Sending PING" >&2
#  echo "PING!"
#  sleep 1
#done | ip netns exec workload1 nc -u 192.168.100.3 5000

