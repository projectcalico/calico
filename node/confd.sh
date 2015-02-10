#!/bin/sh
exec /confd -confdir=/ -debug -interval=5 -watch -verbose -node ${ETCD_IP} >>/var/log/calico/confd.log 2>&1