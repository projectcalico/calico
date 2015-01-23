#!/bin/bash
[ -z $BASH ] && echo "You must run this script in bash" && exit 1
whoami | grep -q "root" || { echo "You must run this script as root" && exit 1; }

#Make sure we are running from the script directory
pushd "$(dirname "$0")"

echo "Collecting diags"

diags_dir=`mktemp -d`
IPTABLES_PREFIX=$diags_dir/iptables
IP6TABLES_PREFIX=$diags_dir/ip6tables
ROUTE_FILE=$diags_dir/route
system=`hostname`
echo "Using directory $diags_dir"

echo DATE=$date > $diags_dir/date
echo $system > $diags_dir/hostname

for cmd in "route -n" "ip route" "ip -6 route"
do
  echo $cmd >> $ROUTE_FILE
  $cmd >> $ROUTE_FILE
  echo >> $ROUTE_FILE
done
netstat -an > $diags_dir/netstat

iptables -v -L > $IPTABLES_PREFIX
iptables -v -L -t nat > $IPTABLES_PREFIX-nat
iptables -v -L -t mangle > $IPTABLES_PREFIX-mangle

#iptables -v -L > $IP6TABLES_PREFIX
#iptables -v -L -t nat > $IP6TABLES_PREFIX-nat
#iptables -v -L -t mangle > $IP6TABLES_PREFIX-mangle

ipset list > $diags_dir/ipset

docker ps -a > $diags_dir/docker

FILENAME=diags-`date +%Y%m%d_%H%M%S`.tar.gz
cp /var/log/calico/* $diags_dir
cp -ra config $diags_dir

tar -zcf $FILENAME --directory $diags_dir .
echo "Diags saved to $diags_dir.gz"
echo "Uploading file. It will be available for 14 days from the following URL"

curl --upload-file $FILENAME https://transfer.sh/$FILENAME
if [[ $diags_dir == /tmp/* ]] ;
then
  rm -rf $diags_dir
fi
popd

