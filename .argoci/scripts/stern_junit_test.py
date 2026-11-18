#!/usr/bin/env python3
"""Tests for stern_junit.py. Run: python3 -m unittest stern_junit_test"""

import os
import subprocess
import sys
import tempfile
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
SCRIPT = os.path.join(HERE, "stern_junit.py")

# Captured verbatim from log_checker.go running in calico/go-build: two excluded
# hits then a real one, and note the closing summary inherits the marker prefix.
REAL_OUTPUT = "+ - + - + \nb ERROR real problem\n+ - Found an error not in the ignore list, exiting\n"


def run(*args):
    return subprocess.run(
        [sys.executable, SCRIPT] + list(args), capture_output=True, text=True
    )


class SternJunit(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _write(self, text, name="check.out"):
        path = os.path.join(self.tmp, name)
        with open(path, "wb") as fh:
            fh.write(text if isinstance(text, bytes) else text.encode())
        return path

    def _emit(self, text, *extra):
        src = self._write(text)
        out = os.path.join(self.tmp, "junit-stern.xml")
        res = run(*(list(extra) + [src, out]))
        return res, out

    def _body(self, out):
        root = ET.parse(out).getroot()
        return root.find("testcase/failure").text

    def test_names_match_sternfail_xml(self):
        res, out = self._emit(REAL_OUTPUT)
        self.assertEqual(res.returncode, 0, res.stderr)
        root = ET.parse(out).getroot()
        self.assertEqual(root.get("name"), "Check Calico component logs")
        case = root.find("testcase")
        self.assertEqual(case.get("name"), "Check for ERRORs in calico component logs")
        self.assertEqual(case.get("classname"), "CheckErrors")
        self.assertEqual(case.find("failure").get("type"), "AssertionError")

    def test_markers_and_trailer_are_stripped(self):
        _, out = self._emit(REAL_OUTPUT)
        body = self._body(out)
        self.assertEqual(body, "b ERROR real problem")
        self.assertNotIn("Found an error not in the ignore list", body)
        self.assertNotIn("+ -", body)

    def test_separator_line_survives(self):
        # A "----------" line is a real log line, not checker marker debris.
        _, out = self._emit("+ \n----------\n")
        self.assertEqual(self._body(out), "----------")

    def test_duplicate_lines_deduped_in_order(self):
        text = "+ \nA ERROR x\n+ \nA ERROR x\n+ \nB error y\n"
        _, out = self._emit(text)
        self.assertEqual(self._body(out).splitlines(), ["A ERROR x", "B error y"])

    def test_ansi_and_control_chars_stripped(self):
        _, out = self._emit("+ \n\x1b[31mA ERROR red\x1b[0m\x07\n")
        self.assertEqual(self._body(out), "A ERROR red")

    def test_invalid_utf8_does_not_crash(self):
        src = self._write(b"+ \nA ERROR \xff\xfe bad bytes\n")
        out = os.path.join(self.tmp, "j.xml")
        res = run(src, out)
        self.assertEqual(res.returncode, 0, res.stderr)
        ET.parse(out)

    def test_oversize_is_truncated_and_still_parses(self):
        lines = "".join("+ \nERROR line %d\n" % i for i in range(5000))
        _, out = self._emit(lines)
        body = self._body(out)
        self.assertIn("[truncated:", body)
        self.assertLessEqual(len(body.splitlines()), 501)
        ET.parse(out)

    def test_single_huge_line_is_hard_cut(self):
        _, out = self._emit("+ \nERROR " + ("x" * 300000) + "\n")
        ET.parse(out)
        self.assertIn("[truncated:", self._body(out))

    def test_empty_input_exits_2(self):
        # log_checker exits 1 on log.Fatalf too, so an empty body is a malfunction.
        res, _ = self._emit("")
        self.assertEqual(res.returncode, 2)

    def test_marker_only_input_exits_2(self):
        res, _ = self._emit("+ - + - \n")
        self.assertEqual(res.returncode, 2)

    def test_pass_mode_has_no_failure(self):
        res, out = self._emit("", "--pass")
        self.assertEqual(res.returncode, 0, res.stderr)
        root = ET.parse(out).getroot()
        self.assertEqual(root.get("failures"), "0")
        self.assertIsNone(root.find("testcase/failure"))
        self.assertEqual(
            root.find("testcase").get("name"),
            "Check for ERRORs in calico component logs",
        )

    def test_verify_accepts_equal_or_larger(self):
        small = self._write('<testsuite><testcase name="a"/></testsuite>', "s.xml")
        big = self._write(
            '<testsuites><testsuite><testcase name="a"/>'
            '<testcase name="b"/></testsuite></testsuites>',
            "b.xml",
        )
        self.assertEqual(run("--verify", big, small).returncode, 0)

    def test_verify_rejects_lost_testcases(self):
        small = self._write('<testsuite><testcase name="a"/></testsuite>', "s.xml")
        big = self._write(
            '<testsuites><testsuite><testcase name="a"/>'
            '<testcase name="b"/></testsuite></testsuites>',
            "b.xml",
        )
        self.assertEqual(run("--verify", small, big).returncode, 1)

    def test_verify_rejects_unparseable(self):
        bad = self._write("not xml at all", "bad.xml")
        good = self._write('<testsuite><testcase name="a"/></testsuite>', "g.xml")
        self.assertEqual(run("--verify", bad, good).returncode, 1)


if __name__ == "__main__":
    unittest.main()
