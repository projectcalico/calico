# -*- coding: utf-8 -*-
# Copyright 2014, 2015 Metaswitch Networks
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
import uuid

if sys.version_info < (2, 7):
    import unittest2 as unittest
else:
    import unittest

import calico.felix.futils as futils

# Logger
log = logging.getLogger(__name__)

UNIQUE_SHORTEN_TESTS = [
    # Tries to return the input string if it can.
    ("foo", 10, "foo"),
    ("foobarbaz1", 10, "foobarbaz1"),
    # Too long, truncated hash
    ("foobarbaz12", 10, '_d71c1ff3e'),
    ("foobarbaz12", 9, '_94df2800'),
    # Different input, different hash
    ("foobarbaz123", 10, '_438f419f9'),
    # This is OK, it starts with the prefix but it's the wrong length so it
    # can't clash with our output:
    ("_foobar", 10, "_foobar"),
    # But this is not since it's the same length as our output and starts with
    # a _.
    ("_foobar", 7, "_9f4764"),
    ("_78c38617f", 10, '_f13be85cf'),
]


class TestFutils(unittest.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

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

    def test_uniquely_shorten(self):
        for inp, length, exp in UNIQUE_SHORTEN_TESTS:
            output = futils.uniquely_shorten(inp, length)
            self.assertTrue(len(output) <= length)
            self.assertEqual(exp, output, "Input %r truncated to length %s "
                                          "should have given output "
                                          "%r but got %r" %
                                          (inp, length, exp, output))

class TestStats(unittest.TestCase):
    def setUp(self):
        self.sc = futils.StatCounter("foo")

    def tearDown(self):
        try:
            futils._registered_diags.remove(("foo", self.sc._dump))
        except ValueError:
            pass

    def test_stats_counter(self):
        self.assertTrue(("foo", self.sc._dump) in futils._registered_diags)
        self.sc.increment("bar")
        self.sc.increment("baz")
        self.assertEqual(self.sc.stats["bar"], 1)
        self.sc.increment("bar")
        self.assertEqual(self.sc.stats["bar"], 2)
        m_log = mock.Mock(spec=logging.Logger)
        self.sc._dump(m_log)
        m_log.assert_has_calls([
            mock.call.info("%s: %s", "bar", 2),
            mock.call.info("%s: %s", "baz", 1),
        ])

    def test_dump_diags(self):
        with mock.patch("calico.felix.futils.stat_log") as m_log:
            self.sc.increment("bar")
            futils.dump_diags()
            m_log.assert_has_calls([
                mock.call.info("=== DIAGNOSTICS ==="),
                mock.call.info("--- %s ---", "foo"),
                mock.call.info("%s: %s", "bar", 1),
                mock.call.info("=== END OF DIAGNOSTICS ==="),
            ], any_order=True)

    def test_dump_diags_cover(self):
        with mock.patch("calico.felix.futils.stat_log") as m_log:
            m_log.info.side_effect = Exception()
            m_log.exception.side_effect = Exception()
            futils.dump_diags()