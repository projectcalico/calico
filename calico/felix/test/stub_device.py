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
felix.test.stub_device
~~~~~~~~~~~~

Stub version of the device module.
"""
import logging
from calico.felix import futils

# Logger
log = logging.getLogger(__name__)

taps = dict()

def reset():
    taps.clear

def add_tap(tap):
    log.debug("Adding new tap interface : %s" % tap.id)
    taps[tap.id] = tap

def del_tap(tap_id):
    del taps[tap_id]

class TapInterface(object):
    def __init__(self, id, v4_ips=[], v6_ips=[]):
        self.id = id
        self.v4_ips = set()
        self.v6_ips = set()

#*****************************************************************************#
#* Methods that match the real interface.                                    *#
#*****************************************************************************#
def tap_exists(tap_id):
    return tap_id in taps

def list_tap_ips(type, tap_id):
    if type == futils.IPV4:
        return taps[tap_id].v4_ips
    else:
        return taps[tap_id].v6_ips

def configure_tap(tap_id):
    pass

def add_route(type, ip, tap_id, mac):
    if type == futils.IPV4:
        taps[tap_id].v4_ips.add(ip)
    else:
        taps[tap_id].v6_ips.add(ip)

def del_route(type, ip, tap_id):
    if type == futils.IPV4:
        taps[tap_id].v4_ips.remove(ip)
    else:
        taps[tap_id].v6_ips.remove(ip)
