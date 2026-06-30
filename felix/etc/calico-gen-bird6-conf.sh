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

# BIRD 3 is a single unified daemon: the IPv4 generator writes the main
# /etc/bird config (router id, kernel/device/direct/filters for both address
# families) which includes /etc/bird/conf.d/*.conf. This script only needs to
# (re)generate the IPv6 BGP peer protocol into that shared include directory
# (AFI-prefixed "ipv6-" so it never clashes with the IPv4 generator's files)
# and reload the single "bird" service.
CONF_DIR=/etc/bird/conf.d
PEER_CONF=$CONF_DIR/ipv6-calico-rr.conf

BIRD_CONF_PEER_TEMPLATE=/usr/share/calico/bird/calico-bird6-peer.conf.template

# Require 4 arguments.
[ $# -eq 4 ] || cat <<EOF

Usage: $0 <my-ipv4-address> <my-ipv6-address> <rr-ipv6-address> <as-number>

where
  <my-ipv4-address> is the external IPv4 address of the local machine
  <my-ipv6-address> is the external IPv6 address of the local machine
  <rr-ipv6-address> is the IPv6 address of the route reflector that
      the local BIRD6 should peer with
  <as-number> is the BGP AS number that the route reflector is using.

Please specify exactly these 4 required arguments.

EOF
[ $# -eq 4 ] || exit -1

# Name the arguments.
my_ipv4_address=$1
my_ipv6_address=$2
rr_ipv6_address=$3
as_number=$4

# Generate the IPv6 route-reflector peering config into the shared include
# directory.
mkdir -p $CONF_DIR
sed -e "
s/@ID@/N1/;
s/@DESCRIPTION@/Connection to BGP route reflector/;
s/@MY_IPV6_ADDRESS@/$my_ipv6_address/;
s/@PEER_IPV6_ADDRESS@/$rr_ipv6_address/;
s/@AS_NUMBER@/$as_number/;
" < $BIRD_CONF_PEER_TEMPLATE > $PEER_CONF

echo "BIRD IPv6 peer configuration generated at $PEER_CONF"

service bird restart
echo "BIRD restarted"
