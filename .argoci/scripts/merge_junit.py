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


def suite_stats(suite):
    """Count a suite's cases by status, from the testcase elements themselves.

    Counting cases (rather than trusting the suite's own attributes) keeps the
    aggregates correct for producers that omit or mis-set them.
    """
    tests = failures = errors = skipped = 0
    for case in suite.findall("testcase"):
        tests += 1
        if case.find("error") is not None:
            errors += 1
        elif case.find("failure") is not None:
            failures += 1
        elif case.find("skipped") is not None:
            skipped += 1
    return tests, failures, errors, skipped


def suite_time(suite):
    # Prefer the suite's own time attribute; fall back to summing its cases'.
    try:
        return float(suite.get("time", ""))
    except ValueError:
        total = 0.0
        for case in suite.findall("testcase"):
            try:
                total += float(case.get("time", ""))
            except ValueError:
                pass
        return total


def main():
    if len(sys.argv) != 3:
        sys.exit(f"usage: {sys.argv[0]} <dir> <output>")
    src_dir, out_path = sys.argv[1], sys.argv[2]
    out_abs = os.path.abspath(out_path)

    # Sort both walk axes so the merged suite order is deterministic (and
    # alphabetical) — the ArgoCI viewer renders suites in file order.
    suites = []
    for dirpath, dirnames, filenames in os.walk(src_dir):
        # Prune diags subtrees at any depth.  Diags are unpacked captures of
        # arbitrary node state (see repack_diags in calicotest's basetest.py), so
        # any junit-shaped XML inside one is by construction a copy of a report
        # from elsewhere -- merging it would double-count, and on exactly the runs
        # (failures) where the numbers get scrutinised.  Non-junit XML in diags
        # (libvirt domain definitions, say) is already filtered out by the
        # root-element check in collect_suites.
        dirnames[:] = sorted(d for d in dirnames if d != "diags")
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

    # Populate aggregate attributes on the root: consumers that read totals off
    # <testsuites> instead of summing its children would otherwise see 0 tests
    # and treat a passing run as empty.
    tests = failures = errors = skipped = 0
    time_total = 0.0
    for suite in suites:
        t, f, e, s = suite_stats(suite)
        tests += t
        failures += f
        errors += e
        skipped += s
        time_total += suite_time(suite)
    merged.set("tests", str(tests))
    merged.set("failures", str(failures))
    merged.set("errors", str(errors))
    merged.set("skipped", str(skipped))
    merged.set("time", f"{time_total:.3f}")

    ET.ElementTree(merged).write(out_path, encoding="utf-8", xml_declaration=True)
    print(
        f"[INFO] merge_junit: wrote {len(suites)} suite(s) "
        f"({tests} tests, {failures} failures, {errors} errors, {skipped} skipped) "
        f"to {out_path}"
    )


if __name__ == "__main__":
    main()
