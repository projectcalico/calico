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
felix.test.test_futils
~~~~~~~~~~~

Test Felix utils.
"""
import logging
import mock
import os
import sys
import unittest
import uuid

import calico.felix.futils as futils

# Logger
log = logging.getLogger(__name__)

class TestFutils(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_time_ms(self):
        # Bit feeble, but validate that we can call it and get back something.
        time_ms = futils.time_ms()

    def test_good_check_call(self):
        # Test a command. Result must include "calico" given where it is run from.
        args = ["ls"]
        result = futils.check_call(args)
        self.assertNotEqual(result.stdout, None)
        self.assertNotEqual(result.stderr, None)
        self.assertTrue("calico" in result.stdout)
        self.assertEqual(result.stderr, "")

    def test_bad_check_call(self):
        # Test an invalid command - must parse but not return anything.
        try:
            args = ["ls", "wibble_wobble"]
            futils.check_call(args)
            self.assertTrue(False)
        except futils.FailedSystemCall as e:
            self.assertNotEqual(e.retcode, 0)
            self.assertEqual(list(e.args), args)
            self.assertNotEqual(e.stdout, None)
            self.assertNotEqual(e.stderr, None)
            self.assertTrue("wibble_wobble" in str(e))

    def test_good_call_silent(self):
        # Test a command. Result must include "calico" given where it is run from.
        args = ["ls"]
        retcode = futils.call_silent(args)
        self.assertEqual(retcode, 0)

    def test_bad_call_silent(self):
        # Test an invalid command - must parse but not return anything.       
        args = ["ls", "wibble_wobble"]
        retcode = futils.call_silent(args)
        self.assertNotEqual(retcode, 0)

    def stub_store_calls(self, args):
        log.debug("Args are : %s", args)
        self.assertEqual(args[0], "bash")
      
        with open(args[1], 'r') as f:
            self.data = f.read()          

    def test_multi_call(self):
        # Test multiple command calls; this just stores the command values.
        ops = [ ["ls"], ["ls", "calico"] ]
        expected = "set -e\n"
        for op in ops:
            cmd = " ".join(op) + "\n"
            expected += "echo Executing : " + cmd + cmd

        with mock.patch('calico.felix.futils.check_call', side_effect=self.stub_store_calls):
            result = futils.multi_call(ops)

        self.assertEqual(expected, self.data)

