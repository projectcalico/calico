# -*- coding: utf-8 -*-
# Copyright 2014 Metaswitch Networks
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
felix.test.stub_devices
~~~~~~~~~~~~

Stub version of the devices module.
"""
import logging
from calico.felix import futils

# Logger
log = logging.getLogger(__name__)

ifaces = dict()

def reset():
    ifaces.clear

def add_interface(tap):
    log.debug("Adding new tap interface : %s" % tap.id)
    ifaces[tap.id] = tap

def del_interface(iface_id):
    del ifaces[iface_id]

class TapInterface(object):
    def __init__(self, id, v4_ips=[], v6_ips=[]):
        self.id = id
        self.v4_ips = set()
        self.v6_ips = set()

#*****************************************************************************#
#* Methods that match the real interface.                                    *#
#*****************************************************************************#
def interface_exists(iface_id):
    return iface_id in ifaces

def list_interface_ips(type, iface_id):
    if type == futils.IPV4:
        return ifaces[iface_id].v4_ips.copy()
    else:
        return ifaces[iface_id].v6_ips.copy()

def configure_interface(iface_id):
    pass

def add_route(type, ip, iface_id, mac):
    if type == futils.IPV4:
        ifaces[iface_id].v4_ips.add(ip)
    else:
        ifaces[iface_id].v6_ips.add(ip)

def del_route(type, ip, iface_id):
    if type == futils.IPV4:
        ifaces[iface_id].v4_ips.remove(ip)
    else:
        ifaces[iface_id].v6_ips.remove(ip)

def interface_up(if_name):
    return True
