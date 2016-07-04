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

BIRD_CONF_TEMPLATE=/usr/share/calico/bird/calico-bird.conf.template
BIRD_CONF_PEER_TEMPLATE=/usr/share/calico/bird/calico-bird-peer.conf.template

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

# Generate peer-independent BIRD config.
mkdir -p $(dirname $BIRD_CONF)
sed -e "
s/@MY_IP_ADDRESS@/$my_ip_address/;
" < $BIRD_CONF_TEMPLATE > $BIRD_CONF

# Generate config to peer with route reflector.
sed -e "
s/@ID@/N1/;
s/@DESCRIPTION@/Connection to BGP route reflector/;
s/@MY_IP_ADDRESS@/$my_ip_address/;
s/@PEER_IP_ADDRESS@/$rr_ip_address/;
s/@AS_NUMBER@/$as_number/;
" < $BIRD_CONF_PEER_TEMPLATE >> $BIRD_CONF

echo BIRD configuration generated at $BIRD_CONF

service bird restart
echo BIRD restarted
