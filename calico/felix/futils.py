# -*- coding: utf-8 -*-

# Copyright (c) 2014 Metaswitch Networks
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

"""
felix.futils
~~~~~~~~~~~~

Felix utilities.
"""
import logging
import os
import re
import subprocess
import time

from calico.felix.config import Config

# Logger
log = logging.getLogger(__name__)

# Flag to indicate "IP v4" or "IP v6"; format that can be printed in logs.
IPV4 = "IPv4"
IPV6 = "IPv6"

# Regexes for IP addresses.
IPV4_REGEX = re.compile("^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")
IPV6_REGEX = re.compile("^[a-f0-9]+:[:a-f0-9]+$")
PORT_REGEX = re.compile("^(([0-9]+)|([0-9]+-[0-9]+))$")
INT_REGEX  = re.compile("^[0-9]+$")

def call_silent(args):
    """
    Wrapper round subprocess_call that discards all of the output to both
    stdout and stderr. *args* must be a list.
    """
    retcode = subprocess.call(args,
                              stdout=open('/dev/null', 'w'),
                              stderr=subprocess.STDOUT)

    return retcode
