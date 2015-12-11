#!/bin/sh
exec 2>&1
sed "s/HOSTNAME/$HOSTNAME/" /etc/calico/confd/templates/bird_aggr.toml.template > /etc/calico/confd/conf.d/bird_aggr.toml
sed "s/HOSTNAME/$HOSTNAME/" /etc/calico/confd/templates/bird6_aggr.toml.template > /etc/calico/confd/conf.d/bird6_aggr.toml
exec confd -confdir=/etc/calico/confd -interval=5 -watch --log-level=debug \
           -node ${ETCD_SCHEME:=http}://${ETCD_AUTHORITY} -client-key=${ETCD_KEY_FILE} \
           -client-cert=${ETCD_CERT_FILE} -client-ca-keys=${ETCD_CA_CERT_FILE}
           scheme=${ETCD_SCHEME:=http}
