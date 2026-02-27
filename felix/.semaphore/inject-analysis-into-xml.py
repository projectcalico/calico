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

Usage: inject-analysis-into-xml.py <json-file> <xml-file> [<xml-file> ...]

Reads fv-tests-guru JSON output (mapping test names to analysis text),
finds matching failed test cases in JUnit XML files, and prepends the
analysis into the <system-out> element of each matched test case.

Pure stdlib implementation (xml.etree.ElementTree + json), no external
dependencies required.
"""

import json
import re
import sys
import xml.etree.ElementTree as ET


def normalize_name(name):
    """Normalize a test name for fuzzy matching."""
    name = re.sub(r'\s+', ' ', name.strip())
    return name.lower()


def find_matching_analysis(test_name, analyses, used_keys):
    """Find the best matching analysis for a test name.

    Tries exact match, then normalized match, then substring match.
    Returns (analysis_text, matched_key) or (None, None).
    """
    # 1. Exact match.
    if test_name in analyses and test_name not in used_keys:
        return analyses[test_name], test_name

    # 2. Normalized match.
    norm_test = normalize_name(test_name)
    for key, text in analyses.items():
        if key in used_keys:
            continue
        if normalize_name(key) == norm_test:
            return text, key

    # 3. Substring match (JSON key is substring of XML name or vice versa).
    for key, text in analyses.items():
        if key in used_keys:
            continue
        norm_key = normalize_name(key)
        if norm_key in norm_test or norm_test in norm_key:
            return text, key

    return None, None


def format_analysis_block(analysis_text):
    """Format the analysis text with a clear header/footer."""
    header = "=" * 60
    return (
        f"\n{header}\n"
        f"  AI FAILURE ANALYSIS (fv-tests-guru)\n"
        f"{header}\n\n"
        f"{analysis_text}\n\n"
        f"{header}\n\n"
    )


def inject_into_xml(json_path, xml_paths):
    """Inject analysis from JSON into matching failed tests in XML files."""
    with open(json_path, 'r') as f:
        analyses = json.load(f)

    if not isinstance(analyses, dict) or not analyses:
        print(f"inject-analysis: No analyses found in {json_path}", file=sys.stderr)
        return

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
            failure = testcase.find('failure')
            if failure is None:
                continue

            test_name = testcase.get('name', '')
            if not test_name:
                continue

            analysis_text, matched_key = find_matching_analysis(
                test_name, analyses, used_keys
            )
            if analysis_text is None:
                continue

            used_keys.add(matched_key)

            # Prepend analysis to system-out.
            analysis_block = format_analysis_block(analysis_text)

            system_out = testcase.find('system-out')
            if system_out is None:
                system_out = ET.SubElement(testcase, 'system-out')
                system_out.text = analysis_block
            else:
                existing = system_out.text or ''
                system_out.text = analysis_block + existing

            modified = True
            total_injected += 1

        if modified:
            tree.write(xml_path, encoding='unicode', xml_declaration=True)
            print(f"inject-analysis: Updated {xml_path}")

    print(f"inject-analysis: Injected analysis into {total_injected} test case(s).")


def main():
    if len(sys.argv) < 3:
        print(
            f"Usage: {sys.argv[0]} <json-file> <xml-file> [<xml-file> ...]",
            file=sys.stderr,
        )
        sys.exit(1)

    json_path = sys.argv[1]
    xml_paths = sys.argv[2:]
    inject_into_xml(json_path, xml_paths)


if __name__ == '__main__':
    main()
