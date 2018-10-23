---
title: Configuring Conntrack
redirect_from: latest/usage/configuration/conntrack
canonical_url: 'https://docs.projectcalico.org/v3.3/usage/configuration/conntrack'
---

A common problem on Linux systems is running out of space in the
conntrack table, which can cause poor iptables performance. This can
happen if you run a lot of workloads on a given host, or if your
workloads create a lot of TCP connections or bidirectional UDP streams.

To avoid this becoming a problem, we recommend increasing the conntrack
table size. To do so, run the following commands:

    sysctl -w net.netfilter.nf_conntrack_max=1000000
    echo "net.netfilter.nf_conntrack_max=1000000" >> /etc/sysctl.conf
