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
if [ -f /etc/bird.conf ]; then
    BIRD_CONF=/etc/bird.conf
else
    BIRD_CONF=/etc/bird/bird.conf
fi

TEMPLATE_DIR=${TEMPLATE_DIR:-/usr/share/calico/bird}
BIRD_CONF_TEMPLATE=${TEMPLATE_DIR}/calico-bird.conf.template
BIRD_CONF_PEER_TEMPLATE=${TEMPLATE_DIR}/calico-bird-peer.conf.template

# Require at least 2 arguments.
[ $# -ge 2 ] || cat <<EOF

Usage: $0 <my-ip-address> <as-number> <peer-ip-address> ...

where
  <my-ip-address> is the external IP address of the local machine
  <as-number> is the BGP AS number that we should use
  each <peer-ip-address> is the IP address of another BGP speaker that
      the local BIRD should peer with.

EOF
[ $# -ge 2 ] || exit -1

# Name the arguments.
my_ip_address=$1
shift
as_number=$1
shift
peer_ips="$@"

# Generate peer-independent BIRD config.
mkdir -p $(dirname $BIRD_CONF)
sed -e "
s/@MY_IP_ADDRESS@/$my_ip_address/;
" < $BIRD_CONF_TEMPLATE > $BIRD_CONF

# Generate peering config.
for peer_ip in $peer_ips; do
    sed -e "
s/@ID@/$peer_ip/;
s/@DESCRIPTION@/Connection to $peer_ip/;
s/@MY_IP_ADDRESS@/$my_ip_address/;
s/@PEER_IP_ADDRESS@/$peer_ip/;
s/@AS_NUMBER@/$as_number/;
" < $BIRD_CONF_PEER_TEMPLATE >> $BIRD_CONF
done

echo BIRD configuration generated at $BIRD_CONF

service bird restart
echo BIRD restarted
