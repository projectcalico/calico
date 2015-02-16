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
felix.test.stub_fiptables
~~~~~~~~~~~~

Stub versions of functions for the fiptables module.
"""
from calico.felix import fiptables
from calico.felix.futils import IPV4, IPV6
from copy import deepcopy
import difflib
import logging

# Logger
log = logging.getLogger(__name__)

class UnexpectedStateException(Exception):
    def __init__(self, actual, expected):
        super(UnexpectedStateException, self).__init__(
            "iptables state does not match")
        self.diff = "\n".join(difflib.unified_diff(
            expected.split("\n"),
            actual.split("\n")))

        self.actual = actual
        self.expected = expected

    def __str__(self):
        return ("%s\nDIFF:\n%s\nACTUAL:\n%s\nEXPECTED\n%s" %
                (self.message, self.diff, self.actual, self.expected))

class TableState(fiptables.TableState):
    """
    Defines the current state of iptables - which rules exist in which
    tables. Normally there will be two - the state that the test generates, and
    the state that the test expects to have at the end. At the end of the test,
    these can be compared.
    """
    def __init__(self):
        super(TableState, self).__init__()

        # tables_v4 and tables_v6 are the internal state of the tables; real_v4
        # and real_v6 are the tables as written out. Just after "apply" or
        # "reset", the two will match, but if you fail to call "apply" then the
        # two will diverge.
        self.real_v4 = {}
        self.real_v6 = {}

        self.reset()

    def apply(self):
        """
        Replace fiptables.Table.apply() with this function.
        """
        log.debug("Overwriting table changes to real state")
        self.real_v4 = deepcopy(self.tables_v4)
        self.real_v6 = deepcopy(self.tables_v4)

    def reset(self):
        """
        Set up the state of the tables as if clean.
        """
        # TODO: This is a bit weird; it makes the test work, but isn't
        # very clear or logical. Better if it cleared tables_* and
        # left real_* unchanged, while read_table then just loaded from
        # real_v4.
        log.debug("Reset table state")

        self.tables_v4.clear()

        table = fiptables.Table(IPV4, "filter")
        table.get_chain("INPUT")
        table.get_chain("OUTPUT")
        table.get_chain("FORWARD")
        table.get_chain("OUTPUT")
        table.get_chain("FORWARD")
        self.tables_v4["filter"] = table

        table = fiptables.Table(IPV4, "nat")
        table.get_chain("PREROUTING")
        table.get_chain("POSTROUTING")
        table.get_chain("INPUT")
        table.get_chain("OUTPUT")
        self.tables_v4["nat"] = table

        self.tables_v6.clear()
        table = fiptables.Table(IPV6, "filter")
        table.get_chain("INPUT")
        table.get_chain("OUTPUT")
        table.get_chain("FORWARD")
        self.tables_v6["filter"] = table

    def check_state(self, expected_state):
        """
        Checks that the current state matches the expected state. Throws an
        exception if it does not.
        """
        actual = str(self)
        expected = str(expected_state)

        if actual != expected:
            raise UnexpectedStateException(actual, expected)


    def __str__(self):
        """
        Convert a full state to a readable string to use in matches and compare
        for final testing. Note that we compare only what is actually written,
        not what is just pending writing.
        """
        table_list = ([ self.real_v4[name]
                        for name in sorted(self.real_v4.keys()) ] +
                      [ self.real_v6[name]
                        for name in sorted(self.real_v6.keys()) ] )

        output = "".join([str(table) for table in table_list])

        return output

