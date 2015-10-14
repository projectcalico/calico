#! /bin/bash

# The bird config file path is different for Red Hat and Debian/Ubuntu.
if [ -f /etc/bird.conf ]; then
    BIRD_CONF=/etc/bird.conf
else
    BIRD_CONF=/etc/bird/bird.conf
fi

BIRD_CONF_TEMPLATE=/usr/share/calico/bird/calico-bird.conf.template

# Require 3 arguments.
[ $# -eq 3 ] || cat <<EOF

Usage: $0 <my-ip-address> <rr-ip-address> <as-number>

where
  <my-ip-address> is the external IP address of the local machine
  <rr-ip-address> is the IP address of the route reflector that
      the local BIRD should peer with
  <as-number> is the BGP AS number that the route reflector is using.

Please specify exactly these 3 required arguments.

EOF
[ $# -eq 3 ] || exit -1

# Name the arguments.
my_ip_address=$1
rr_ip_address=$2
as_number=$3

# Generate BIRD config file.
mkdir -p $(dirname $BIRD_CONF)
sed -e "
s/@MY_IP_ADDRESS@/$my_ip_address/;
s/@RR_IP_ADDRESS@/$rr_ip_address/;
s/@AS_NUMBER@/$as_number/;
" < $BIRD_CONF_TEMPLATE > $BIRD_CONF

echo BIRD configuration generated at $BIRD_CONF

service bird restart
echo BIRD restarted
