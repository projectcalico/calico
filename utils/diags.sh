#!/bin/bash
[ -z $BASH ] && echo "You must run this script in bash" && exit 1
if [ "$LOGNAME" != "root" ]
then
  echo "You must run this script as root"
  exit 1
fi

echo "Collecting diags"

ROUTE_FILE=route
CALICO_CFG=/etc/calico
CALICO_DIR=/var/log/calico
NEUTRON_DIR=/var/log/neutron
date=`date +"%F_%H-%M-%S"`
diags_dir=/tmp/"$date"
system=`hostname`
echo "  created dir $diags_dir"
mkdir "$diags_dir"
pushd "$diags_dir" > /dev/null

echo "  storing system state..."

echo DATE=$date > date
echo $system > hostname

dpkg -l "nova*" "neutron*" "calico*" 2>&1 > dpkg

for cmd in "route -n" "ip route" "ip -6 route" "ip rule list"
do
  echo $cmd >> $ROUTE_FILE
  $cmd >> $ROUTE_FILE
  echo >> $ROUTE_FILE
done

netstat -an > netstat
iptables-save > iptables
ip6tables-save > ip6tables
ipset list > ipset
ip -6 neigh > ip6neigh

echo "  copying log files..."

cp -a "$CALICO_DIR" .
cp -a "$NEUTRON_DIR" .
cp -a "$CALICO_CFG" etc_calico

mkdir logs
cp /var/log/syslog* logs
cp /var/log/messages* logs

echo "  compressing..."
cd ..
tar -zcf "$diags_dir.tar.gz" "$date"
rm -r "$date"

popd > /dev/null

echo "Diags saved to \"$diags_dir.tar.gz\""

