# -*- coding: utf-8 -*-
# Copyright (c) 2014-2016 Tigera, Inc. All rights reserved.
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
from subprocess import CalledProcessError

import mock

import unittest2

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


class TestFutils(unittest2.TestCase):
    def setUp(self):
        pass

    def tearDown(self):
        pass

    def test_good_check_call(self):
        with mock.patch("calico.felix.futils._call_semaphore",
                        wraps=futils._call_semaphore) as m_sem:
            # Test a command. Result must include "calico" given where it is
            # run from.
            args = ["ls"]
            result = futils.check_call(args)
            self.assertNotEqual(result.stdout, None)
            self.assertNotEqual(result.stderr, None)
            self.assertTrue("calico" in result.stdout)
            self.assertEqual(result.stderr, "")
            self.assertTrue(m_sem.__enter__.called)

    def test_bad_check_call(self):
        # Test an invalid command - must parse but not return anything.
        args = ["ls", "wibble_wobble"]
        try:
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

    def test_safe_truncate(self):
        self.assert_safe_truncate("foobarbazb", 10, "foobarbazb")
        # Yes, this gets longer, which is silly.  However, there's no point
        # making the code complicated to handle this case that should never be
        # hit.
        self.assert_safe_truncate("foobarbazb", 9, "fooba...<snip>...bazb")
        self.assert_safe_truncate(None, 9, None)
        self.assert_safe_truncate(1234, 9, "1234")

    def assert_safe_truncate(self, s, length, expected):
        result = futils.safe_truncate(s, length)
        self.assertEqual(result, expected,
                         "Expected %r to be truncated as %r but got %r" %
                         (s, expected, result))

    def test_longest_prefix(self):
        self.assertEqual(futils.find_longest_prefix([]), None)
        self.assertEqual(futils.find_longest_prefix(["a"]), "a")
        self.assertEqual(futils.find_longest_prefix(["a", ""]), "")
        self.assertEqual(futils.find_longest_prefix(["a", "ab"]), "a")
        self.assertEqual(futils.find_longest_prefix(["ab", "ab"]), "ab")
        self.assertEqual(futils.find_longest_prefix(["ab", "ab", "abc"]), "ab")
        self.assertEqual(futils.find_longest_prefix(["abc", "ab", "ab"]), "ab")
        self.assertEqual(futils.find_longest_prefix(["ab", "cd"]), "")
        self.assertEqual(futils.find_longest_prefix(["tapabcd", "tapacdef"]), "tapa")

    @mock.patch("os.path.exists", autospec=True)
    @mock.patch("calico.felix.futils.check_call", autospec=True)
    @mock.patch("calico.felix.futils.Popen", autospec=True)
    def test_detect_ipv6_supported(self, m_popen, m_check_call, m_exists):
        m_popen.return_value.communicate.return_value = "", ""
        m_exists.return_value = True
        self.assertEqual(futils.detect_ipv6_supported(), (True, None))

    @mock.patch("os.path.exists", autospec=True)
    @mock.patch("calico.felix.futils.check_call", autospec=True)
    @mock.patch("calico.felix.futils.Popen", autospec=True)
    def test_ipv6_compiled_out(self, m_popen, m_check_call, m_exists):
        m_popen.return_value.communicate.return_value = "", ""
        m_exists.return_value = False
        self.assertEqual(futils.detect_ipv6_supported(), (False, mock.ANY))

    @mock.patch("os.path.exists", autospec=True)
    @mock.patch("calico.felix.futils.check_call", autospec=True)
    @mock.patch("calico.felix.futils.Popen", autospec=True)
    def test_ipv6_missing_ip6tables(self, m_popen, m_check_call, m_exists):
        m_popen.return_value.communicate.return_value = "", ""
        m_exists.return_value = True
        m_check_call.side_effect = futils.FailedSystemCall()
        self.assertEqual(futils.detect_ipv6_supported(), (False, mock.ANY))

    @mock.patch("os.path.exists", autospec=True)
    @mock.patch("calico.felix.futils.check_call", autospec=True)
    @mock.patch("calico.felix.futils.Popen", autospec=True)
    def test_ipv6_missing_rpfilter(self, m_popen, m_check_call, m_exists):
        m_exists.return_value = True
        m_popen.return_value.communicate.return_value = (
            None,
            "ip6tables vA.B.C: Couldn't load match `rpfilter':No such file or "
            "directory"
        )
        self.assertEqual(futils.detect_ipv6_supported(), (False, mock.ANY))

    @mock.patch("os.path.exists", autospec=True)
    @mock.patch("calico.felix.futils.check_call", autospec=True)
    @mock.patch("calico.felix.futils.Popen", autospec=True)
    def test_ipv6_missing_rpfilter_error(self, m_popen, m_check_call, m_exists):
        m_exists.return_value = True
        m_popen.side_effect = OSError()
        self.assertEqual(futils.detect_ipv6_supported(), (False, mock.ANY))

    @mock.patch("os.path.exists", autospec=True)
    @mock.patch("calico.felix.futils.check_call", autospec=True)
    def test_ipv6_missing_nat_table(self, m_check_call, m_exists):
        m_exists.return_value = True
        m_check_call.side_effect = iter([None, futils.FailedSystemCall()])
        self.assertEqual(futils.detect_ipv6_supported(), (False, mock.ANY))

    @mock.patch("calico.felix.futils.urllib3.disable_warnings", autospec=True)
    @mock.patch("calico.felix.futils.urllib3.util.retry.Retry", autospec=True)
    @mock.patch("calico.felix.futils.urllib3.PoolManager", autospec=True)
    def test_report_usage_and_get_warnings(self, m_poolmanager, m_retry, m_disable):
        status = mock.Mock()
        status.status.side_effect = "200"
        status.data.decode.side_effect = "the reply"
        http = mock.Mock()
        http.request.side_effect = status
        m_poolmanager.return_value = http
        m_disable.return_value = "hello"
        m_retry.return_value = "Hello"
        futils.report_usage_and_get_warnings("1.4.0", "calico01", "123", "100", "NA")

    @mock.patch("sys.exit")
    @mock.patch("os.path.exists", autospec=True)
    @mock.patch("calico.felix.futils.check_call", autospec=True)
    @mock.patch("calico.felix.futils.check_output", autospec=True)
    def test_command_deps_mainline(self, m_check_output, m_check_call,
                                    m_exists, m_exit):
        m_check_output.return_value = "v1.2.3"
        futils.check_command_deps()
        self.assertFalse(m_exit.called)

    @mock.patch("os.path.exists", autospec=True)
    @mock.patch("calico.felix.futils.check_call", autospec=True)
    @mock.patch("calico.felix.futils.check_output", autospec=True)
    def test_command_deps_fail(self, m_check_output, m_check_call,
                                m_exists):
        futils.check_command_deps()
        num_check_calls = m_check_call.call_count
        self.assertEqual(num_check_calls, 2,
                         msg="Calls to check_call: %s" %
                             m_check_call.mock_calls)
        num_check_outputs = m_check_output.call_count
        self.assertEqual(num_check_outputs, 3,
                         msg="Calls to check_output: %s" %
                             m_check_output.mock_calls)
        m_check_output.return_value = "v1.2.3"

        # Run through all the check_call invocations raising an error from
        # each.
        for exc in [futils.FailedSystemCall(), OSError()]:
            for ii in xrange(num_check_calls):
                # Raise from the ii'th check_call.
                log.info("Raising %s from the %s check_call",
                         exc, ii)
                m_check_call.reset_mock()
                m_check_call.side_effect = iter(([None] * ii) + [exc])
                self.assertRaises(SystemExit, futils.check_command_deps)
                self.assertEqual(ii+1, m_check_call.call_count)

        # Run through all the check_output invocations raising an error from
        # each.
        m_check_call.side_effect = None
        for exc in [CalledProcessError(1, "foo"), OSError()]:
            for ii in xrange(num_check_outputs):
                # Raise from the ii'th check_output.
                m_check_output.reset_mock()
                m_check_output.side_effect = iter(([None] * ii) + [exc])
                self.assertRaises(SystemExit, futils.check_command_deps)
                self.assertEqual(ii+1, m_check_output.call_count)


class TestStats(unittest2.TestCase):
    def setUp(self):
        futils._registered_diags = []
        self.sc = futils.StatCounter("foo")

    def tearDown(self):
        futils._registered_diags = []

    def test_stats_counter(self):
        self.assertTrue(("foo", self.sc._dump) in futils._registered_diags)
        self.sc.increment("bar")
        self.sc.increment("baz")
        self.assertEqual(self.sc.stats["bar"], 1)
        self.sc.increment("bar")
        self.assertEqual(self.sc.stats["bar"], 2)
        self.sc.increment("baz", by=2)
        self.assertEqual(self.sc.stats["baz"], 3)
        m_log = mock.Mock(spec=logging.Logger)
        self.sc._dump(m_log)
        self.assertEqual(m_log.info.mock_calls, [
            mock.call("%s: %s", "bar", 2),
            mock.call("%s: %s", "baz", 3),
        ])

    def test_dump_diags(self):
        with mock.patch("calico.felix.futils.stat_log") as m_log:
            self.sc.increment("bar")
            futils.dump_diags()
            self.assertEqual(m_log.info.mock_calls,
                             [
                                 mock.call("=== DIAGNOSTICS ==="),
                                 mock.call("--- %s ---", "foo"),
                                 mock.call("%s: %s", "bar", 1),
                                 mock.call("=== END OF DIAGNOSTICS ==="),
                             ])

    def test_dump_diags_process(self):
        process_results = [
            ('Execution time in user mode (seconds)', 'ru_utime', 1),
            ('Execution time in kernel mode (seconds)', 'ru_stime', 2),
            ('Maximum Resident Set Size (KB)', 'ru_maxrss', 3),
            ('Soft page faults', 'ru_minflt', 4),
            ('Hard page faults', 'ru_majflt', 5),
            ('Input events', 'ru_inblock', 6),
            ('Output events', 'ru_oublock', 7),
            ('Voluntary context switches', 'ru_nvcsw', 8),
            ('Involuntary context switches', 'ru_nivcsw', 9),
        ]

        with mock.patch('calico.felix.futils.stat_log') as m_log:
            with mock.patch('calico.felix.futils.resource') as m_resource:
                res = m_resource.getrusage.return_value
                for _, field, val in process_results:
                    setattr(res, field, val)

                calls = [
                    mock.call.info('=== DIAGNOSTICS ==='),
                    mock.call.info("--- %s ---", "foo"),
                    mock.call.info('--- %s ---', 'Process Statistics'),
                    mock.call.info('=== END OF DIAGNOSTICS ==='),
                ]
                calls.extend(
                    mock.call.info('%s: %s', name, value) for name, _, value
                    in process_results
                )

                futils.register_process_statistics()
                futils.dump_diags()
                m_log.assert_has_calls(calls, any_order=True)

    def test_dump_diags_cover(self):
        with mock.patch("calico.felix.futils.stat_log") as m_log:
            m_log.info.side_effect = Exception()
            m_log.exception.side_effect = Exception()
            futils.dump_diags()
