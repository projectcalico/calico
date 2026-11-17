# Copyright (c) 2015-2026 Tigera, Inc. All rights reserved.
#
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

"""
This file contains settings values used by the test suite.
"""
from collections import namedtuple
import os

_MY_DIR = os.path.dirname(os.path.realpath(__file__))
_MY_PARENT_DIR = os.path.dirname(_MY_DIR)
_MY_CONFIG_DIR = os.path.join(_MY_PARENT_DIR, "config")

# Location of the file that describes the cluster's layout: its nodes, their roles
# and how to reach them.  By default this is in this tree's config/ directory, which
# is /calico-test/config in the openstack-e2e image.
LAYOUT_FILE = os.path.join(_MY_CONFIG_DIR, "cluster-layout.conf")

# Local diags directory into which diags from failed tests are downloaded
LOCAL_DIAGS_DIR = "diags"

# name: the image's name in Glance.
# username and password: the default login info for the images OS
# flavor: the OpenStack hardware specs to boot with
# boot_time: the maximum number of times to try connecting to an instance that
#   is booting or restarting with this image.  Each connection attempt takes
#   about a minute, so boot_time should be set to about twice the number of
#   minutes that the image would normally take to boot.
# active_time: the number of times to test for ACTIVE state after launching an
#   instance, or VERIFY_RESIZE state after migrating an instance.  Each
#   connection attempt takes about a second, so active_time should be set to
#   about twice the number of seconds that an instance using this image would
#   normally take to reach that state.  Typical test runs show that the worst
#   case for the IPv6-enabled image is about 50s; and for the CirrOS image is
#   about 25s.
Image = namedtuple("Image", "name username password flavor boot_time active_time")
CIRROS = Image("cirros-x86_64", "cirros", "gocubsgo", "m1.tiny", 4, 60)
IPV6_WITH_APPS = Image("ipv6_enabled_image", "ubuntu", "ubuntu", "m1.small", 10, 120)

# name: the string OpenStack will use to identify the image.
# cidr: the IPv4 subnet for this network
# cidr_v6: the IPv6 subnet for this network

# Note that IP subnets MUST NOT overlap in Calico - make sure the definitions
# below do not overlap!
Network = namedtuple("Network", "name cidr cidr_v6")
DEFAULT_NET_NAME = "demo-net"
# Each region needs its own default network, we allocate those on demand in
# tenant.py.
DEFAULT_NETS = [
    Network(DEFAULT_NET_NAME, "10.28.0.0/17", "fd5f:5d21:845:1c2e:2::/80"),
    Network(DEFAULT_NET_NAME, "10.28.128.0/17", "fd5f:5d21:845:1c2e:5::/80"),
]
IPV4_ONLY = Network("ipv4-net", "10.29.0.0/16", None)
# If you plan to use the IPv6 functionality, you must use the IPV6 image.
IPV_BOTH = Network("ipv-both", "10.29.0.0/16", "fd5f:5d21:845:1c2e:3::/80")
FLOAT_IPV4 = Network("float-ipv4", "172.16.1.0/24", None)

# Maximum number of rules to add in the large security group test.
OPENSTACK_MAX_RULES_IN_TEST = 800

# Maximum number of security groups to add in the many security group test.
OPENSTACK_MAX_GROUPS_IN_TEST = 50

# Default number of rules and groups
OPENSTACK_DEF_RULES = 20
OPENSTACK_DEF_GROUPS = 20

# Directory containing dpkgs for installation onto rig VMs.  These are
# fetched from the Debian archive when the e2e image is built - see the
# Dockerfile, which must agree with the filenames here.
DPKGS_DIR = os.path.join(_MY_PARENT_DIR, "dpkgs")
IPERF_DPKG_PATH = os.path.join(DPKGS_DIR, "iperf_2.0.5-3_amd64.deb")
SCAPY_DPKG_PATH = os.path.join(DPKGS_DIR, "python-scapy_2.2.0-1_all.deb")

# Directory containing scripts
SCRIPTS_DIR = os.path.join(_MY_DIR, "scripts")
SEND_PACKET_SCRIPT = os.path.join(SCRIPTS_DIR, "send_packet.py")

# How to invoke etcdctl.
ETCDCTL_V3 = "ETCDCTL_API=3 etcdctl --user root:rootpasswd"
