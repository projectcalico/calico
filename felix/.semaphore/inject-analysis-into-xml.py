#!/usr/bin/env python3

# Copyright (c) 2026 Tigera, Inc. All rights reserved.
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

"""inject-analysis-into-xml.py - Inject fv-tests-guru analysis into JUnit XML.

Usage: inject-analysis-into-xml.py [--diags-log <path>] <json-file> [<xml-file> ...]

Reads fv-tests-guru JSON output and finds matching failed test cases in
JUnit XML files, prepending the analysis into the <system-out> element.

With --diags-log, also writes a human-readable diagnostics log file
(test-NNN-DIAGS.log) that is pushed as a Semaphore artifact alongside
the test-NNN-FAILED.log.

Supports the fv-tests-guru output format:
  {"failures": [{"description": "TestName", "diagnosis": "...", ...}, ...]}

Pure stdlib implementation (xml.etree.ElementTree + json), no external
dependencies required.
"""

import json
import re
import sys
import xml.etree.ElementTree as ET


def normalize_name(name):
    """Normalize a test name for fuzzy matching."""
    # Strip Ginkgo node type markers like [It], [BeforeEach], etc.
    name = re.sub(r'\[(?:It|BeforeEach|AfterEach|JustBeforeEach|JustAfterEach|BeforeSuite|AfterSuite)\]\s*', '', name)
    name = re.sub(r'\s+', ' ', name.strip())
    return name.lower()


def parse_analyses(data):
    """Parse fv-tests-guru JSON into a {description: failure_dict} map.

    Expected format:
      {
        "failures": [
          {
            "description": "TestName/subtest",
            "diagnosis": "...",
            "error_message": "...",
            "bpf_verifier_log": "...",
            "file_path": "...",
            "line_number": "...",
            ...
          }
        ]
      }
    """
    if not isinstance(data, dict):
        return {}

    failures = data.get('failures')
    if not isinstance(failures, list):
        return {}

    analyses = {}
    for f in failures:
        desc = f.get('description', '')
        if not desc:
            continue
        analyses[desc] = f

    return analyses


def find_matching_analysis(test_name, analyses, used_keys):
    """Find the best matching analysis for a test name.

    Tries exact match, then normalized match, then substring match.
    Returns (failure_dict, matched_key) or (None, None).
    """
    # 1. Exact match.
    if test_name in analyses and test_name not in used_keys:
        return analyses[test_name], test_name

    # 2. Normalized match.
    norm_test = normalize_name(test_name)
    for key, entry in analyses.items():
        if key in used_keys:
            continue
        if normalize_name(key) == norm_test:
            return entry, key

    # 3. Substring match (JSON key is substring of XML name or vice versa).
    for key, entry in analyses.items():
        if key in used_keys:
            continue
        norm_key = normalize_name(key)
        if norm_key in norm_test or norm_test in norm_key:
            return entry, key

    return None, None


def format_summary(failure):
    """Extract a concise one-line summary for the failure message attribute."""
    # Prefer explicit summary field if fv-tests-guru provides one.
    text = failure.get('summary', '') or failure.get('diagnosis', '')
    if not text:
        return None
    # Use the first non-empty line.
    for line in text.splitlines():
        line = line.strip()
        if line:
            if len(line) > 200:
                return "[AI] " + line[:197] + "..."
            return "[AI] " + line
    return None


def format_analysis_block(failure):
    """Format a failure entry with a clear header/footer."""
    header = "=" * 60
    parts = [f"\n{header}", "  AI FAILURE ANALYSIS (fv-tests-guru)", header, ""]

    diagnosis = failure.get('diagnosis', '')
    if diagnosis:
        parts.append(diagnosis)
        parts.append("")

    file_path = failure.get('file_path', '')
    line_number = failure.get('line_number', '')
    if file_path:
        loc = file_path
        if line_number:
            loc += f":{line_number}"
        parts.append(f"Location: {loc}")
        parts.append("")

    parts.append(header)
    parts.append("")
    return "\n".join(parts)


def write_diags_log(json_path, output_path):
    """Write a human-readable diagnostics log from fv-tests-guru JSON output."""
    with open(json_path, 'r') as f:
        data = json.load(f)

    analyses = parse_analyses(data)
    if not analyses:
        print(f"inject-analysis: No failure analyses to write to {output_path}", file=sys.stderr)
        return

    sep = "=" * 60
    lines = []
    for desc, entry in analyses.items():
        lines.append(sep)
        lines.append(f"  Test: {desc}")
        lines.append(sep)
        lines.append("")

        diagnosis = entry.get('diagnosis', '')
        if diagnosis:
            lines.append(diagnosis)
            lines.append("")

    with open(output_path, 'w') as f:
        f.write("\n".join(lines))

    print(f"inject-analysis: Wrote diagnostics log to {output_path}")


def inject_into_xml(json_path, xml_paths):
    """Inject analysis from JSON into matching failed tests in XML files."""
    with open(json_path, 'r') as f:
        data = json.load(f)

    analyses = parse_analyses(data)
    if not analyses:
        print(f"inject-analysis: No failure analyses found in {json_path}", file=sys.stderr)
        return

    print(f"inject-analysis: Parsed {len(analyses)} failure(s) from {json_path}")

    used_keys = set()
    total_injected = 0

    for xml_path in xml_paths:
        try:
            tree = ET.parse(xml_path)
        except ET.ParseError as e:
            print(f"inject-analysis: Failed to parse {xml_path}: {e}", file=sys.stderr)
            continue

        root = tree.getroot()
        modified = False

        # Find all testcase elements with failure children.
        for testcase in root.iter('testcase'):
            failure_elem = testcase.find('failure')
            if failure_elem is None:
                continue

            test_name = testcase.get('name', '')
            if not test_name:
                continue

            failure_entry, matched_key = find_matching_analysis(
                test_name, analyses, used_keys
            )
            if failure_entry is None:
                continue

            used_keys.add(matched_key)

            # Put the full analysis in a custom <ai-diags> element.
            ai_diags = ET.SubElement(testcase, 'ai-diags')
            ai_diags.text = format_analysis_block(failure_entry)

            # Replace the failure body with the AI summary.
            summary = format_summary(failure_entry)
            if summary:
                failure_elem.text = summary

            modified = True
            total_injected += 1

        if modified:
            tree.write(xml_path, encoding='unicode', xml_declaration=True)
            print(f"inject-analysis: Updated {xml_path}")

    print(f"inject-analysis: Injected analysis into {total_injected} test case(s).")


def main():
    args = sys.argv[1:]
    diags_log_path = None

    # Parse optional --diags-log <path> flag.
    if '--diags-log' in args:
        idx = args.index('--diags-log')
        if idx + 1 < len(args):
            diags_log_path = args[idx + 1]
            args = args[:idx] + args[idx + 2:]
        else:
            print(f"Usage: --diags-log requires a path argument", file=sys.stderr)
            sys.exit(1)

    if len(args) < 1 or (len(args) < 2 and not diags_log_path):
        print(
            f"Usage: {sys.argv[0]} [--diags-log <path>] <json-file> [<xml-file> ...]",
            file=sys.stderr,
        )
        sys.exit(1)

    json_path = args[0]
    xml_paths = args[1:]

    if diags_log_path:
        write_diags_log(json_path, diags_log_path)

    if xml_paths:
        inject_into_xml(json_path, xml_paths)


if __name__ == '__main__':
    main()
