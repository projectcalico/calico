#!/usr/bin/env python3
"""Merge JUnit/xUnit XML files into a single <testsuites> report.

Usage: merge_junit.py <dir> <output>

Scans <dir> recursively for *.xml files whose root element is <testsuite> or
<testsuites>, and writes all of the contained <testsuite> elements under a single
<testsuites> root at <output>.  This turns a report tree of many per-class files (e.g.
the openstack-e2e runner's xmlrunner output, one TEST-*.xml per test class) into the
single-file form that the ArgoCI viewer renders as one test report with collapsible
suites.

Best-effort by design, since it runs from the CI epilogue: files that fail to parse
(or whose root is some other XML) are skipped with a warning, and if no suites are
found at all, no output is written and the exit code is still 0.
"""

import os
import sys
import xml.etree.ElementTree as ET

# Parse with defusedxml when available (XXE / entity-expansion hardening).  The
# inputs are our own test runner's output, but they do transit a test container, so
# prefer the hardened parser; fall back to stdlib (whose expat has built-in
# billion-laughs limits on modern images) rather than fail the epilogue.
try:
    from defusedxml.ElementTree import parse as xml_parse
except ImportError:
    xml_parse = ET.parse


def collect_suites(path):
    # Catch broadly, not just ParseError: defusedxml signals rejected content with
    # its own exception types, and a bad input file must never fail the epilogue.
    try:
        root = xml_parse(path).getroot()
    except Exception as e:
        print(f"[WARN] merge_junit: skipping {path}: {e}", file=sys.stderr)
        return []
    if root.tag == "testsuite":
        return [root]
    if root.tag == "testsuites":
        return root.findall("testsuite")
    return []


def main():
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <dir> <output>")
    src_dir, out_path = sys.argv[1], sys.argv[2]
    out_abs = os.path.abspath(out_path)

    # Sort both walk axes so the merged suite order is deterministic (and
    # alphabetical) — the ArgoCI viewer renders suites in file order.
    suites = []
    for dirpath, dirnames, filenames in os.walk(src_dir):
        dirnames.sort()
        for fn in sorted(filenames):
            path = os.path.join(dirpath, fn)
            if not fn.lower().endswith(".xml") or os.path.abspath(path) == out_abs:
                continue
            suites.extend(collect_suites(path))

    if not suites:
        print(
            f"[INFO] merge_junit: no JUnit XML found under {src_dir}; nothing to merge"
        )
        return

    merged = ET.Element("testsuites")
    merged.extend(suites)
    ET.ElementTree(merged).write(out_path, encoding="utf-8", xml_declaration=True)
    print(f"[INFO] merge_junit: wrote {len(suites)} suite(s) to {out_path}")


if __name__ == "__main__":
    main()
