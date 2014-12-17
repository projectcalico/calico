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
felix.test.stub_ipsets
~~~~~~~~~~~~

Stub version of the ipsets module.
"""
import logging
from calico.felix import futils

# Logger
log = logging.getLogger(__name__)

ipsets = dict()

def reset():
    ipsets.clear

class StubIpset(object):
    def __init__(self, name, typename, family):
        self.name = name
        self.typename = typename
        self.family = family
        self.entries = set()

    def __str__(self):
        return("Name: %s\nType: %s (%s)\nMembers:\n" %
               (self.name, self.typename, self.family,
                "\n".join(sorted(self.entries))))

class StubIpsetError(Exception):
    pass


class UnexpectedStateException(Exception):
    def __init__(self, actual, expected):
        super(UnexpectedStateException, self).__init__(
            "ipsets state does not match")
        self.diff = "\n".join(difflib.unified_diff(
            expected.split("\n"),
            actual.split("\n")))

        self.actual = actual
        self.expected = expected

    def __str__(self):
        return ("%s\nDIFF:\n%s\nACTUAL:\n%s\nEXPECTED\n%s" %
                (self.message, self.diff, self.actual, self.expected))


def check_state(expected_ipsets):
    """
    Checks that the current state matches the expected state. Throws an
    exception if it does not.
    """
    actual = "\n".join([str(ipsets[name]) for name in sorted(ipsets.keys())])
    expected = "\n".join([str(expected_ipsets[name]) for name in sorted(expected_ipsets.keys())])

    if actual != expected:
        raise UnexpectedStateException(actual, expected)

#*****************************************************************************#
#* Methods that match the real interface.                                    *#
#*****************************************************************************#
def swap(name1, name2):
    ipset1 = ipsets[name1]
    ipset2 = ipsets[name2]
    if ipset1.typename != ipset2.typename:
        raise StubIpsetError(
            "Cannot swap ipset %s of type %s with ipset %s of type %s" %
            (name1, ipset1.typename, name2, ipset2.typename))

    if ipset1.family != ipset2.family:
        raise StubIpsetError(
            "Cannot swap ipset %s of family %s with ipset %s of family %s" %
            (name1, ipset1.family, name2, ipset2.family))

    tmp = ipset1.entries
    ipset1.entries = ipset2.entries
    ipset2.entries = tmp


def flush(name):
    ipsets[name].entries.clear()

def create(name, typename, family):
    if name not in ipsets:
        ipsets[name] = StubIpset(name, typename, family)

def destroy(name):
    if name in ipsets:
        del ipsets[name]

def add(name, value):
    ipsets[name].entries.add(value)

def list_names():
    return ipsets.keys()
