#!/bin/bash
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

# A cron cannot include another workflow, so the nightly repeats the CI
# workflow's module list. The nightly exists to cover the lanes a diff gates
# out, so a module missing from it is one nothing scheduled ever runs — and
# nothing else would say so.

set -euo pipefail

ci="${1:-.argoci/ciworkflow.yaml}"
cron="${2:-.argoci/cron/nightly-ci.yaml}"

includes() {
    python3 -c '
import sys, yaml
d = yaml.safe_load(open(sys.argv[1])) or {}
for i in d.get("includes", []):
    print(i if isinstance(i, str) else i["path"])
' "$1" | sort
}

if diff_out=$(diff <(includes "$ci") <(includes "$cron")); then
    echo "[INFO] $cron covers every module in $ci"
    exit 0
fi

echo "[ERROR] the nightly and the CI workflow include different modules:"
echo "${diff_out}" | sed 's/^</  only in CI:    /; s/^>/  only in cron:  /'
exit 1
