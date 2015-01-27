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
felix.ipsets
~~~~~~~~~~~~

IP sets management functions.
"""
import logging

from calico.felix import futils
from calico.felix.futils import IPV4, IPV6

def swap(name1, name2):
    """
    Swap the two ipsets of the supplied names.
    """
    return futils.check_call(["ipset", "swap", name1, name2])

def flush(name):
    """
    Flush an ipset.
    """
    futils.check_call(["ipset", "flush", name])

def create(name, typename, family):
    """
    Create an ipset. If it already exists, do nothing.

    *name* is the name of the ipset.
    *typename* must be a valid type, such as "hash:net" or "hash:net,port"
    *family* must be *inet* or *inet6*
    """
    if futils.call_silent(["ipset", "list", name]) != 0:
        # ipset list failed - either does not exist, or an error. Either way,
        # try creation, throwing an error if it does not work.
        futils.check_call(["ipset", "create", name, typename, "family", family])

def destroy(name):
    """
    Destroy an ipset if it exists (and do nothing if not).
    """
    if futils.call_silent(["ipset", "list", name]) == 0:
        futils.check_call(["ipset", "destroy", name])

def add(name, value):
    """
    Add a value to an ipset.
    """
    futils.check_call(["ipset", "add", name, value, "-exist"])

def list_names():
    """
    List all names of ipsets. Note that this is *not* the same as the ipset
    list command which lists contents too (hence the name change).
    """
    data  = futils.check_call(["ipset", "list"]).stdout
    lines = data.split("\n")

    names = []

    for line in lines:
        words = line.split()
        if (len(words) > 1 and words[0] == "Name:"):
            names.append(words[1])

    return names
