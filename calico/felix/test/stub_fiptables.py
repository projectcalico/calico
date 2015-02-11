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

class TableState(object):
    """
    Defines the current state of iptables - which rules exist in which
    tables. Normally there will be two - the state that the test generates, and
    the state that the test expects to have at the end. At the end of the test,
    these can be compared.
    """
    def __init__(self):
        self.tables_v4 = {}
        self.tables_v6 = {}
        self.tables = []
        self.reset()

    def get_table(self, type, name):
        """
        Replace fiptables.get_table with this function.
        """
        if type == IPV4:
            table = self.tables_v4[name]
        else:
            table = self.tables_v6[name]
        return deepcopy(table)

    def apply(self, table):
        """
        Replace fiptables.Table.apply() with this function.
        """
        log.debug("Apply batched changes to table %s (%s)",
                  table.name,
                  table.type)

        log.debug("Table applied :\n%s", table)

        if table.type == IPV4:
            self.tables_v4[table.name] = table
        else:
            self.tables_v6[table.name] = table

        log.debug("State now :\n%s", self)

    def reset(self):
        """
        Clear the state of the tables, getting them back to being empty.
        """
        self.tables_v4.clear()

        table = fiptables.Table(IPV4, "filter")
        fiptables.Chain(table, "INPUT")
        fiptables.Chain(table, "OUTPUT")
        fiptables.Chain(table, "FORWARD")
        fiptables.Chain(table, "OUTPUT")
        fiptables.Chain(table, "FORWARD")
        self.tables_v4["filter"] = table

        table = fiptables.Table(IPV4, "nat")
        fiptables.Chain(table, "PREROUTING")
        fiptables.Chain(table, "POSTROUTING")
        fiptables.Chain(table, "INPUT")
        fiptables.Chain(table, "OUTPUT")
        self.tables_v4["nat"] = table

        self.tables_v6.clear()
        table = fiptables.Table(IPV6, "filter")
        fiptables.Chain(table, "INPUT")
        fiptables.Chain(table, "OUTPUT")
        fiptables.Chain(table, "FORWARD")
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
        for final testing.
        """
        table_list = ([ self.tables_v4[name]
                        for name in sorted(self.tables_v4.keys()) ] +
                      [ self.tables_v6[name]
                        for name in sorted(self.tables_v6.keys()) ] )

        output = "".join([str(table) for table in table_list])

        return output

