#!/usr/bin/env python3
"""Turn banzai-core log_checker.go output into a JUnit report.

Usage:
  stern_junit.py <checker-stdout> <out.xml>          # a hit: failing testcase
  stern_junit.py --pass <checker-stdout> <out.xml>   # clean: passing testcase
  stern_junit.py --verify <merged.xml> <original.xml>

The suite/case/class names match banzai-core's sternfail.xml byte for byte, so
that queries written against the pre-existing signal keep matching.

The failing case carries the offending log lines. sternfail.xml is a static file
with an empty <failure> body, which made every historic occurrence of this
signal undiagnosable after the run's logs aged out.
"""

import os
import re
import sys
import xml.etree.ElementTree as ET

# Same posture as merge_junit.py: prefer the hardened parser for reading, since
# these documents transit a test container, but do not fail the epilogue when it
# is absent (stdlib expat still caps entity expansion on modern images).
try:
    from defusedxml.ElementTree import parse as xml_parse
except ImportError:
    xml_parse = ET.parse

SUITE_NAME = "Check Calico component logs"
CASE_NAME = "Check for ERRORs in calico component logs"
CASE_CLASS = "CheckErrors"
FAILURE_MESSAGE = "Errors found in calico component logs"
FAILURE_TYPE = "AssertionError"

# log_checker prints "+ " per include hit and "- " per exclusion with no newline
# of their own, so they run together ("+ - + - + ") until a non-excluded hit ends
# the run and puts its log line on the next line. Its closing summary inherits
# that prefix, which is why it is stripped rather than matched at line start.
MARKER_RUN = re.compile(r"^(?:\+ |- )+")
CHECKER_TRAILER = "Found an error not in the ignore list, exiting"

ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
# XML 1.0 forbids these outright; lxml/ElementTree emit them and then no parser
# can read the result back.
ILLEGAL_XML = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")

MAX_BYTES = 100 * 1024
MAX_LINES = 500


def clean_lines(raw):
    """Offending log lines, in first-seen order, from the checker's stdout."""
    seen = set()
    out = []
    for line in raw.splitlines():
        line = MARKER_RUN.sub("", line)
        line = ANSI.sub("", line)
        line = ILLEGAL_XML.sub("", line)
        line = line.rstrip()
        if not line or line == CHECKER_TRAILER:
            continue
        # A line matching two include terms is printed once per term.
        if line in seen:
            continue
        seen.add(line)
        out.append(line)
    return out


def truncate(lines):
    """Cap the body, before XML escaping rather than after.

    Escaping expands the text, so trimming afterwards can cut an entity in half
    and produce exactly the unparseable document the cap exists to avoid.
    """
    kept = []
    total = 0
    for i, line in enumerate(lines):
        if len(kept) >= MAX_LINES or total + len(line.encode()) > MAX_BYTES:
            if not kept:  # one line larger than the whole budget
                kept.append(line.encode()[:MAX_BYTES].decode(errors="replace"))
                i += 1
            kept.append("[truncated: %d further lines omitted]" % (len(lines) - i))
            break
        kept.append(line)
        total += len(line.encode()) + 1
    return kept


def build(lines, passing):
    suite = ET.Element(
        "testsuite",
        {
            "name": SUITE_NAME,
            "tests": "1",
            "failures": "0" if passing else "1",
            "errors": "0",
            "time": "0",
        },
    )
    case = ET.SubElement(
        suite, "testcase", {"name": CASE_NAME, "classname": CASE_CLASS, "time": "0"}
    )
    if not passing:
        failure = ET.SubElement(
            case, "failure", {"message": FAILURE_MESSAGE, "type": FAILURE_TYPE}
        )
        failure.text = "\n".join(lines)
    return suite


def count_cases(path):
    root = xml_parse(path).getroot()
    return len(root.findall(".//testcase"))


def verify(merged, original):
    """Refuse a merge that lost testcases.

    merge_junit.py skips inputs it cannot parse and still exits 0, so its exit
    status alone does not prove the merged document is complete -- and the swap
    it feeds overwrites the authoritative ginkgo report.
    """
    try:
        merged_n, original_n = count_cases(merged), count_cases(original)
    except Exception as e:
        print("[WARN] stern_junit: verify failed to parse: %s" % e, file=sys.stderr)
        return 1
    if merged_n < original_n:
        print(
            "[WARN] stern_junit: merged report has %d testcases, original had %d; "
            "refusing to replace it" % (merged_n, original_n),
            file=sys.stderr,
        )
        return 1
    return 0


def main():
    argv = sys.argv[1:]
    if len(argv) == 3 and argv[0] == "--verify":
        return verify(argv[1], argv[2])

    passing = len(argv) == 3 and argv[0] == "--pass"
    if passing:
        argv = argv[1:]
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 1
    src, out_path = argv

    lines = []
    if not passing:
        try:
            with open(src, "r", errors="replace") as fh:
                lines = clean_lines(fh.read())
        except OSError as e:
            print("[WARN] stern_junit: cannot read %s: %s" % (src, e), file=sys.stderr)
            return 1
        if not lines:
            # log_checker exits 1 both for a real hit and for log.Fatalf, so an
            # empty body means it died rather than found something.
            print(
                "[WARN] stern_junit: no log lines survived parsing; "
                "treating as a checker malfunction, not a hit",
                file=sys.stderr,
            )
            return 2
        lines = truncate(lines)

    try:
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        ET.ElementTree(build(lines, passing)).write(
            out_path, encoding="utf-8", xml_declaration=True
        )
    except OSError as e:
        print("[WARN] stern_junit: cannot write %s: %s" % (out_path, e), file=sys.stderr)
        return 1
    print(
        "[INFO] stern_junit: wrote %s (%s)"
        % (out_path, "clean" if passing else "%d line(s)" % len(lines))
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
