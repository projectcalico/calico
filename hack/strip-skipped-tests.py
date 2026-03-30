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

"""Strip skipped test cases from JUnit XML files.

Ginkgo marks tests matched by -skip or -skip-package as "skipped" in JUnit
reports. This clutters the Semaphore test results UI with hundreds of entries
that weren't actually run. This script removes those entries in-place.

Usage: strip-skipped-tests.py report/*.xml
"""

import sys
import xml.etree.ElementTree as ET


def strip_skipped(path):
    tree = ET.parse(path)
    root = tree.getroot()
    for suite in root.iter("testsuite"):
        to_remove = [tc for tc in suite.findall("testcase") if tc.find("skipped") is not None]
        if not to_remove:
            continue
        for tc in to_remove:
            suite.remove(tc)
        remaining = suite.findall("testcase")
        suite.set("tests", str(len(remaining)))
        suite.set("skipped", "0")
    tree.write(path, xml_declaration=True, encoding="unicode")


for path in sys.argv[1:]:
    try:
        strip_skipped(path)
    except Exception as e:
        print(f"Warning: failed to process {path}: {e}", file=sys.stderr)
