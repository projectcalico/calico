#!/usr/bin/env python3
"""Tests for merge_junit.py and the epilogue's use of it.

Run: python3 .argoci/scripts/merge_junit_test.py
"""

import os
import shutil
import subprocess
import tempfile
import unittest
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
MERGE = os.path.join(HERE, "merge_junit.py")
EPILOGUE = os.path.join(HERE, "global_epilogue.sh")


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def suite(name, cases=1):
    body = "".join(f'<testcase name="{name}-{i}"/>' for i in range(cases))
    return f'<testsuite name="{name}">{body}</testsuite>\n'


def tempdir(test):
    d = tempfile.mkdtemp()
    test.addCleanup(shutil.rmtree, d, ignore_errors=True)
    return d


def suite_names(path):
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    return [s.get("name") for s in suites]


def lens_view(report_dir):
    """Suites as the Lens uploader sees them: every .xml directly in the dir."""
    names = []
    for fn in sorted(os.listdir(report_dir)):
        if fn.endswith(".xml"):
            names.extend(suite_names(os.path.join(report_dir, fn)))
    return sorted(names)


class MergeScopeTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempdir(self)
        write(f"{self.dir}/top.xml", suite("top"))
        write(f"{self.dir}/results/TEST-a.xml", suite("a"))
        write(f"{self.dir}/diags/node/copy.xml", suite("diag"))
        write(f"{self.dir}/not-junit.xml", "<domain/>")
        self.out = os.path.join(tempdir(self), "out.xml")

    def merge(self, *args):
        subprocess.run(["python3", MERGE, *args, self.dir, self.out], check=True, capture_output=True)
        return sorted(suite_names(self.out)) if os.path.exists(self.out) else []

    def test_all(self):
        self.assertEqual(self.merge(), ["a", "top"])

    def test_top(self):
        self.assertEqual(self.merge("--scope=top"), ["top"])

    def test_subdirs(self):
        self.assertEqual(self.merge("--scope=subdirs"), ["a"])

    def test_bad_scope(self):
        r = subprocess.run(["python3", MERGE, "--scope=nope", self.dir, self.out], capture_output=True)
        self.assertNotEqual(r.returncode, 0)


class EpilogueTest(unittest.TestCase):
    """Runs the real epilogue with bz/artifact/gsutil/curl stubbed out."""

    def run_epilogue(self, layout):
        root = tempdir(self)
        bin_dir, report, local = f"{root}/bin", f"{root}/report", f"{root}/local"
        os.makedirs(bin_dir)
        os.makedirs(local)
        os.makedirs(f"{root}/logs")
        for tool in ("bz", "artifact", "gsutil", "curl"):
            write(f"{bin_dir}/{tool}", f'#!/bin/sh\necho "{tool} $*" >> {root}/calls.log\n')
            os.chmod(f"{bin_dir}/{tool}", 0o755)
        if layout is not None:
            os.makedirs(report)
            for rel, text in layout.items():
                write(f"{report}/{rel}", text)
        env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", REPORT_DIR=report,
                   BZ_LOCAL_DIR=local, BZ_HOME=root, BZ_LOGS_DIR=f"{root}/logs",
                   CI_STEP_EXIT_CODE="0", VPP_RESULTS_PREFIX="")
        env.pop("GITHUB_ACCESS_TOKEN", None)
        subprocess.run(["bash", EPILOGUE], env=env, check=True, capture_output=True)
        calls = ""
        if os.path.exists(f"{root}/calls.log"):
            with open(f"{root}/calls.log") as f:
                calls = f.read()
        pushed = [ln.split()[3] for ln in calls.splitlines()
                  if ln.startswith("artifact push job") and ("-d junit.xml" in ln or ln.split()[3].endswith("/junit.xml"))]
        viewer = sorted(suite_names(pushed[0])) if pushed else []
        lens = lens_view(report) if layout is not None else []
        return lens, viewer

    def test_single_junit_untouched(self):
        lens, viewer = self.run_epilogue({"junit.xml": suite("e2e")})
        self.assertEqual(lens, ["e2e"])
        self.assertEqual(viewer, ["e2e"])

    def test_junit_plus_bz_install(self):
        lens, viewer = self.run_epilogue({"junit.xml": suite("e2e"), "bz-install.xml": suite("bz install")})
        self.assertEqual(lens, ["bz install", "e2e"])
        self.assertEqual(viewer, ["bz install", "e2e"])

    def test_subdir_reports_reach_lens(self):
        lens, viewer = self.run_epilogue({"results/TEST-A.xml": suite("A"), "results/TEST-B.xml": suite("B")})
        self.assertEqual(lens, ["A", "B"])
        self.assertEqual(viewer, ["A", "B"])

    def test_subdir_reports_plus_bz_install(self):
        lens, viewer = self.run_epilogue({"results/TEST-A.xml": suite("A"), "bz-install.xml": suite("bz install")})
        self.assertEqual(lens, ["A", "bz install"])
        self.assertEqual(viewer, ["A", "bz install"])

    # Several top-level reports and no junit.xml (e.g. scale-test) used to be
    # merged into REPORT_DIR/junit.xml, which Lens then read alongside them.
    def test_top_level_reports_not_duplicated(self):
        lens, viewer = self.run_epilogue({"one.xml": suite("one"), "two.xml": suite("two")})
        self.assertEqual(lens, ["one", "two"])
        self.assertEqual(viewer, ["one", "two"])

    def test_failed_install_only(self):
        lens, viewer = self.run_epilogue({"bz-install.xml": suite("bz install")})
        self.assertEqual(lens, ["bz install"])
        self.assertEqual(viewer, ["bz install"])

    def test_diags_ignored(self):
        lens, viewer = self.run_epilogue({"junit.xml": suite("e2e"), "diags/n/copy.xml": suite("e2e")})
        self.assertEqual(lens, ["e2e"])
        self.assertEqual(viewer, ["e2e"])

    def test_no_report_dir(self):
        self.assertEqual(self.run_epilogue(None), ([], []))


if __name__ == "__main__":
    unittest.main()
