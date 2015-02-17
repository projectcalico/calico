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
felix.test.test_ipsets
~~~~~~~~~~~

Test the ipsets handling code.
"""
import logging
import mock
import os
import sys
import unittest
import uuid

import calico.felix.ipsets as ipsets
import calico.felix.futils as futils

# Logger
log = logging.getLogger(__name__)

class TestIpsets(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_swap(self):
        retcode = futils.CommandOutput("", "")

        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ipsets.swap("a", "b")
            futils.check_call.assert_called_with(["ipset", "swap", "a", "b"])


    def test_flush(self):
        retcode = futils.CommandOutput("", "")

        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ipsets.flush("a")
            futils.check_call.assert_called_with(["ipset", "flush", "a"])

    def test_create(self):
        retcode = futils.CommandOutput("", "")

        with mock.patch('calico.felix.futils.call_silent', return_value=1):
            with mock.patch('calico.felix.futils.check_call', return_value=retcode):
                ipsets.create("a", "b", "c")
                futils.call_silent.assert_called_with(["ipset", "list", "a"])
                futils.check_call.assert_called_with(["ipset", "create", "a", "b", "family", "c"])

        with mock.patch('calico.felix.futils.call_silent', return_value=0):
            with mock.patch('calico.felix.futils.check_call', return_value=retcode):
                ipsets.create("a", "b", "c")
                futils.call_silent.assert_called_with(["ipset", "list", "a"])
                self.assertFalse(futils.check_call.called)

    def test_destroy(self):
        retcode = futils.CommandOutput("", "")

        with mock.patch('calico.felix.futils.call_silent', return_value=0):
            with mock.patch('calico.felix.futils.check_call', return_value=retcode):
                ipsets.destroy("a")
                futils.call_silent.assert_called_with(["ipset", "list", "a"])
                futils.check_call.assert_called_with(["ipset", "destroy", "a"])

        with mock.patch('calico.felix.futils.call_silent', return_value=1):
            with mock.patch('calico.felix.futils.check_call', return_value=retcode):
                ipsets.destroy("a")
                futils.call_silent.assert_called_with(["ipset", "list", "a"])
                self.assertFalse(futils.check_call.called)

    def test_add(self):
        retcode = futils.CommandOutput("", "")

        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            ipsets.add("a", "b")
            futils.check_call.assert_called_with(["ipset", "add", "a", "b", "-exist"])

    def test_list_names(self):
        retcode = futils.CommandOutput(
            "Name: one\nName:a\nblah\nfee fi fo fum\nNomatch\n" +
            "Name:     two\nfdsjk\n\nfdjk\nName:\nb\nName: three\n", "")

        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            names = ipsets.list_names()
            futils.check_call.assert_called_with(["ipset", "list"])
            self.assertEqual(names, ["one", "two", "three"])

        retcode = futils.CommandOutput("", "")

        with mock.patch('calico.felix.futils.check_call', return_value=retcode):
            names = ipsets.list_names()
            futils.check_call.assert_called_with(["ipset", "list"])
            self.assertEqual(names, [])
