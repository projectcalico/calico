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
import difflib

# Logger
log = logging.getLogger(__name__)

def reset():
    ipset_state.reset()

class IpsetState(object):
    def __init__(self):
        self.ipsets = {}

    def reset(self):
        self.ipsets.clear()

    def swap(self, name1, name2):
        ipset1 = self.ipsets[name1]
        ipset2 = self.ipsets[name2]
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

    def flush(self, name):
        self.ipsets[name].entries.clear()

    def create(self, name, typename, family):
        if name not in self.ipsets:
            self.ipsets[name] = StubIpset(name, typename, family)

    def destroy(self, name):
        if name in self.ipsets:
            del self.ipsets[name]

    def add(self, name, value):
        self.ipsets[name].entries.add(value)

    def list_names(self):
        return self.ipsets.keys()


class StubIpset(object):
    def __init__(self, name, typename, family):
        self.name = name
        self.typename = typename
        self.family = family
        self.entries = set()

    def __str__(self):
        return("Name: %s\nType: %s (%s)\nMembers:\n%s\n" %
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
        return ("%s\nDIFF:\n%s\n\nACTUAL:\n%s\nEXPECTED\n%s" %
                (self.message, self.diff, self.actual, self.expected))


def check_state(expected_ipsets):
    """
    Checks that the current state matches the expected state. Throws an
    exception if it does not. Note that we do not check the "tmp" ipsets.
    That is because whether or not they are present is quite complicated,
    and writing test code to duplicate the logic would be pointless, especially
    since we only really care that the right used ipsets exist.
    """
    actual = "\n".join([str(ipset_state.ipsets[name])
                        for name in sorted(ipset_state.ipsets.keys())
                        if "tmp" not in name])
    expected = "\n".join([str(expected_ipsets.ipsets[name])
                          for name in sorted(expected_ipsets.ipsets.keys())
                        if "tmp" not in name])

    if actual != expected:
        raise UnexpectedStateException(actual, expected)

#*****************************************************************************#
#* Methods that match the real interface.                                    *#
#*****************************************************************************#
def swap(name1, name2):
    ipset_state.swap(name1, name2)

def flush(name):
    ipset_state.flush(name)

def create(name, typename, family):
    ipset_state.create(name, typename, family)

def destroy(name):
    ipset_state.destroy(name)

def add(name, value):
    ipset_state.add(name, value)

def list_names():
    return ipset_state.list_names()

# One global variable - the existing state.
ipset_state = IpsetState()
