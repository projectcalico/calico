#!/bin/bash
[ -z $BASH ] && echo "You must run this script in bash" && exit 1
whoami | grep -q "root" || { echo "You must run this script as root" && exit 1; }
echo "Collecting diags"

ROUTE_FILE=route
IPTABLES_PREFIX=iptables
IP6TABLES_PREFIX=ip6tables
CALICO_CFG=/etc/calico
CALICO_DIR=/var/log/calico
NEUTRON_DIR=/var/log/neutron
date=`date +"%F_%H-%M-%S"`
diags_dir="/tmp/$date"
system=`hostname`
echo $diags_dir
mkdir $diags_dir
pushd $diags_dir

echo DATE=$date > date
echo $system > hostname

for cmd in "route -n" "ip route" "ip -6 route"
do
  echo $cmd >> $ROUTE_FILE
  $cmd >> $ROUTE_FILE
  echo >> $ROUTE_FILE
done
netstat -an > netstat

iptables -v -L > $IPTABLES_PREFIX
iptables -v -L -t nat > $IPTABLES_PREFIX-nat
iptables -v -L -t mangle > $IPTABLES_PREFIX-mangle
iptables -v -L > $IP6TABLES_PREFIX
iptables -v -L -t nat > $IP6TABLES_PREFIX-nat
iptables -v -L -t mangle > $IP6TABLES_PREFIX-mangle
ipset list > ipset

cp -a $CALICO_DIR .
cp -a $NEUTRON_DIR .
cp -a $CALICO_CFG etc_calico

mkdir logs
cp /var/log/*log logs

tar -zcf $diags_dir.gz *

popd

echo "Diags saved to $diags_dir.gz"

