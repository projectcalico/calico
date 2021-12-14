#! /bin/bash
# Copyright (c) 2016 Tigera, Inc. All rights reserved.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# The bird config file path is different for Red Hat and Debian/Ubuntu.
if [ -f /etc/bird6.conf ]; then
    BIRD_CONF=/etc/bird6.conf
else
    BIRD_CONF=/etc/bird/bird6.conf
fi

TEMPLATE_DIR=${TEMPLATE_DIR:-/usr/share/calico/bird}
BIRD_CONF_TEMPLATE=${TEMPLATE_DIR}/calico-bird6.conf.template
BIRD_CONF_PEER_TEMPLATE=${TEMPLATE_DIR}/calico-bird6-peer.conf.template

# Require at least 3 arguments.
[ $# -ge 3 ] || cat <<EOF

Usage: $0 <my-ipv4-address> <my-ipv6-address> <as-number> <peer-ipv6-address> ...

where
  <my-ipv4-address> is the external IPv4 address of the local machine
  <my-ipv6-address> is the external IPv6 address of the local machine
  <as-number> is the BGP AS number that we should use
  each <peer-ipv6-address> is the IPv6 address of another BGP speaker that
      the local BIRD should peer with.

EOF
[ $# -ge 3 ] || exit -1

# Name the arguments.
my_ipv4_address=$1
shift
my_ipv6_address=$1
shift
as_number=$1
shift
peer_ips="$@"

# Generate peer-independent BIRD config.
mkdir -p $(dirname $BIRD_CONF)
sed -e "
s/@MY_IPV4_ADDRESS@/$my_ipv4_address/;
" < $BIRD_CONF_TEMPLATE > $BIRD_CONF

# Generate peering config.
for peer_ip in $peer_ips; do
    sed -e "
s/@ID@/$peer_ip/;
s/@DESCRIPTION@/Connection to $peer_ip/;
s/@MY_IPV6_ADDRESS@/$my_ipv6_address/;
s/@PEER_IPV6_ADDRESS@/$peer_ip/;
s/@AS_NUMBER@/$as_number/;
" < $BIRD_CONF_PEER_TEMPLATE >> $BIRD_CONF
done

echo BIRD6 configuration generated at $BIRD_CONF

service bird6 restart
echo BIRD6 restarted
